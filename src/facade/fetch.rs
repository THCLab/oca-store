use super::Facade;
#[cfg(feature = "local-references")]
use crate::local_references;
use crate::{
    data_storage::DataStorage,
    repositories::{OCABundleCacheRepo, OCABundleFTSRepo},
};
use crate::{data_storage::Namespace, repositories::OCABundleFTSRecord};
use log::info;
use oca_ast::{
    ast::{self, NestedValue, OCAAst, ObjectKind, RefValue},
    utils::parse_language_code,
};
use oca_bundle::state::oca_bundle::{OCABundle, capture_base::CaptureBase};
use oca_bundle::{
    build::OCABuildStep,
    state::oca_bundle::{OCABundleModel, overlay::Overlay},
};
use oca_file::ocafile;
use said::SelfAddressingIdentifier;

use serde::{Serialize, ser::SerializeStruct};
#[cfg(feature = "local-references")]
use std::collections::HashMap;
use std::str::FromStr;
use std::{borrow::Borrow, collections::HashSet};

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum OCAObject {
    CaptureBase(CaptureBase),
    Overlay(Overlay),
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    #[serde(rename = "r")]
    pub records: Vec<SearchRecord>,
    #[serde(rename = "m")]
    pub metadata: SearchMetadata,
}

#[derive(Debug, Serialize)]
pub struct SearchRecord {
    pub oca_bundle: OCABundleModel,
    pub metadata: SearchRecordMetadata,
}

#[derive(Debug, Serialize)]
pub struct SearchRecordMetadata {
    pub phrase: String,
    pub scope: String,
    pub score: f32,
}

#[derive(Debug, Serialize)]
pub struct SearchMetadata {
    pub total: usize,
    pub page: usize,
}

#[derive(Debug, Serialize)]
pub struct AllOCABundleResult {
    pub records: Vec<OCABundleModel>,
    pub metadata: AllOCABundleMetadata,
}

#[derive(Debug, Serialize)]
pub struct AllOCABundleMetadata {
    pub total: usize,
    pub page: usize,
}

#[derive(Debug, Serialize)]
pub struct AllCaptureBaseResult {
    pub records: Vec<CaptureBase>,
    pub metadata: AllCaptureBaseMetadata,
}

#[derive(Debug, Clone)]
// #[version(protocol = "OCAA", major = 1, minor = 1)]
pub struct BundleWithDependencies {
    pub bundle: OCABundle,
    pub dependencies: Vec<OCABundle>,
}

impl Serialize for BundleWithDependencies {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BundleWithDependencies", 2)?;
        state.serialize_field("bundle", &self.bundle)?;
        state.serialize_field("dependencies", &self.dependencies)?;
        state.end()
    }
}

#[derive(Debug, Serialize)]
pub struct AllCaptureBaseMetadata {
    pub total: usize,
    pub page: usize,
}

impl Facade {
    pub fn search_oca_bundle(
        &self,
        language: Option<isolang::Language>,
        query: String,
        limit: usize,
        page: usize,
    ) -> SearchResult {
        let oca_bundle_fts_repo = OCABundleFTSRepo::new(self.connection());
        let search_result = oca_bundle_fts_repo.search(language, query, limit, page);
        let records = search_result
            .records
            .iter()
            .map(|record| SearchRecord {
                // TODO
                oca_bundle: self
                    .get_oca_bundle(record.oca_bundle_said.clone())
                    .unwrap()
                    .clone(),
                metadata: SearchRecordMetadata {
                    phrase: record.metadata.phrase.clone(),
                    scope: record.metadata.scope.clone(),
                    score: record.metadata.score,
                },
            })
            .collect();
        SearchResult {
            records,
            metadata: SearchMetadata {
                total: search_result.metadata.total,
                page: search_result.metadata.page,
            },
        }
    }

    /// Build meta data for FTS
    pub fn build_meta(&self, oca_bundle: &OCABundleModel) {
        let meta_overlays = oca_bundle
            .overlays
            .iter()
            .filter_map(|x| {
                let (name, _) = x.name.split_once('/').unwrap_or((x.name.as_str(), ""));
                if name.eq_ignore_ascii_case("meta") {
                    Some(x.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if !meta_overlays.is_empty() {
            let oca_bundle_fts_repo = OCABundleFTSRepo::new(self.connection());
            for meta_overlay in meta_overlays {
                let mut name = "".to_string();
                let mut description = "".to_string();
                let mut language = "".to_string();
                if let NestedValue::Value(s) = meta_overlay
                    .properties
                    .as_ref()
                    .unwrap()
                    .get("name")
                    .unwrap()
                {
                    name = s.to_string();
                }
                if let NestedValue::Value(s) = meta_overlay
                    .properties
                    .as_ref()
                    .unwrap()
                    .get("description")
                    .unwrap_or(&NestedValue::Value("".to_string()))
                {
                    description = s.to_string();
                }
                if let NestedValue::Value(s) = meta_overlay
                    .properties
                    .as_ref()
                    .unwrap()
                    .get("language")
                    .unwrap_or(&NestedValue::Value("".to_string()))
                {
                    language = s.to_string();
                }
                let oca_bundle_fts_record = OCABundleFTSRecord::new(
                    oca_bundle.digest.clone().unwrap().to_string(),
                    name,
                    description,
                    parse_language_code(&language).unwrap(),
                );

                oca_bundle_fts_repo.insert(oca_bundle_fts_record);
            }
        }
    }

    #[cfg(feature = "local-references")]
    pub fn fetch_all_refs(&self) -> Result<HashMap<String, String>, String> {
        let mut refs: HashMap<String, String> = HashMap::new();
        self.db
            .get_all(Namespace::OCAReferences)
            .unwrap()
            .iter()
            .for_each(|(k, v)| {
                refs.insert(k.clone(), String::from_utf8(v.to_vec()).unwrap());
            });
        Ok(refs)
    }

    pub fn fetch_all_oca_bundle(
        &self,
        limit: usize,
        page: usize,
    ) -> Result<AllOCABundleResult, Vec<String>> {
        let mut oca_bundles = vec![];
        let mut total: usize = 0;
        let mut errors = vec![];

        let oca_bundle_cache_repo = OCABundleCacheRepo::new(self.connection());
        let all_oca_bundle_records = oca_bundle_cache_repo.fetch_all(limit, page);
        for all_oca_bundle_record in all_oca_bundle_records {
            if total == 0 {
                total = all_oca_bundle_record.total;
            }
            if let Some(cache_record) = all_oca_bundle_record.cache_record {
                match serde_json::from_str(&cache_record.oca_bundle) {
                    Ok(oca_bundle) => {
                        oca_bundles.push(oca_bundle);
                    }
                    Err(e) => {
                        errors.push(format!("Failed to parse oca bundle: {}", e));
                    }
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(AllOCABundleResult {
            records: oca_bundles,
            metadata: AllOCABundleMetadata { total, page },
        })
    }

    pub fn fetch_all_capture_base(
        &self,
        limit: usize,
        page: usize,
    ) -> Result<AllCaptureBaseResult, Vec<String>> {
        let mut capture_bases = vec![];
        let mut total: usize = 0;
        let mut errors = vec![];

        let capture_base_cache_repo =
            crate::repositories::CaptureBaseCacheRepo::new(self.connection());
        let all_capture_base_records = capture_base_cache_repo.fetch_all(limit, page);
        for all_capture_base_record in all_capture_base_records {
            if total == 0 {
                total = all_capture_base_record.total;
            }
            if let Some(cache_record) = all_capture_base_record.cache_record {
                match serde_json::from_str(&cache_record.capture_base) {
                    Ok(capture_base) => {
                        capture_bases.push(capture_base);
                    }
                    Err(e) => {
                        errors.push(format!("Failed to parse capture base: {}", e));
                    }
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(AllCaptureBaseResult {
            records: capture_bases,
            metadata: AllCaptureBaseMetadata { total, page },
        })
    }

    /// Retrive OCA object (capture_base or overlay) from local storage by its SAID
    /// # Arguments
    /// * `saids` - Vector of SAIDs to retrive OCA objects
    ///
    /// # Return
    /// * `Result<Vec<OCAObject>, Vec<String>>` - Vector of OCA objects or vector of errors
    pub fn get_oca_objects(&self, saids: Vec<String>) -> Result<Vec<OCAObject>, Vec<String>> {
        let mut result: Vec<OCAObject> = vec![];
        let mut errors: Vec<String> = vec![];

        for said in saids {
            let r = self
                .db_cache
                .get(Namespace::OCAObjectsJSON, &said)
                .map_err(|e| {
                    errors.push(e.to_string());
                    errors.clone()
                })?;
            let object_str = String::from_utf8(r.ok_or_else(|| {
                errors.push(format!("No OCA Object found for said: {}", said));
                errors.clone()
            })?)
            .unwrap();
            let r_type = self
                .db
                .get(Namespace::OCARelations, &format!("{}.metadata", said))
                .map_err(|e| {
                    errors.push(e.to_string());
                    errors.clone()
                })?;
            let o_type: ObjectKind = (*r_type.unwrap().first().unwrap()).into();
            match o_type {
                ObjectKind::CaptureBase(_) => result.push(OCAObject::CaptureBase(
                    serde_json::from_str::<CaptureBase>(&object_str).map_err(|e| {
                        errors.push(format!("Failed to parse OCA object: {}", e));
                        errors.clone()
                    })?,
                )),
                ObjectKind::Overlay(_) => {
                    let oca_overlay = OCAObject::Overlay(
                        serde_json::from_str::<Overlay>(&object_str).map_err(|e| {
                            errors.push(format!("Failed to parse OCA object: {}", e));
                            errors.clone()
                        })?,
                    );
                    result.push(oca_overlay);
                }
                _ => {}
            };
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(result)
    }

    /// Retrive OCA Bundle Set (bundle + dependencies) from local storage by its SAID
    /// # Arguments
    /// * `said` - Said of the OCA bundle Set
    /// # return
    /// * `Result<BundleWithDependencies, Vec<String>>` - OCA bundle set or vector of errors
    pub fn get_oca_bundle_set(
        &self,
        said: SelfAddressingIdentifier,
    ) -> Result<BundleWithDependencies, Vec<String>> {
        let seen = &mut HashSet::new();
        get_oca_bundle_set(self.db_cache.borrow(), said, true, seen)
    }

    /// Retrive OCA Bundle from local storage by its SAID
    /// # Arguments
    /// * `said` - Said of the OCA bundle model
    ///
    /// # Return
    /// * `Result<OCABundleModel, Vec<String>>` - OCA bundle model or vector of errors
    ///
    pub fn get_oca_bundle(
        &self,
        said: SelfAddressingIdentifier,
    ) -> Result<OCABundleModel, Vec<String>> {
        let bundle_model = get_oca_bundle_model(self.db_cache.borrow(), said).unwrap();
        Ok(bundle_model)
    }

    pub fn get_oca_bundle_steps(
        &self,
        said: SelfAddressingIdentifier,
    ) -> Result<Vec<OCABuildStep>, Vec<String>> {
        let mut said = said.to_string();
        #[allow(clippy::borrowed_box)]
        fn extract_operation(
            db: &Box<dyn DataStorage>,
            said: &String,
        ) -> Result<(String, oca_ast::ast::Command), Vec<String>> {
            let r = db
                .get(Namespace::OCA, &format!("oca.{}.operation", said))
                .map_err(|e| vec![format!("{}", e)])?
                .ok_or_else(|| vec![format!("No history found for said: {}", said)])?;

            let said_length = r.first().unwrap();
            let parent_said = String::from_utf8_lossy(&r[1..*said_length as usize + 1]).to_string();
            let op_length = r.len() - *said_length as usize - 1;
            let op = String::from_utf8_lossy(
                &r[*said_length as usize + 1..*said_length as usize + 1 + op_length],
            )
            .to_string();

            match serde_json::from_str::<oca_ast::ast::Command>(&op) {
                Ok(command) => Ok((parent_said, command)),
                Err(e) => Err(vec![format!("Failed to parse command: {}", e)]),
            }
        }

        let mut history: Vec<OCABuildStep> = vec![];

        loop {
            let (parent_said, command) = extract_operation(&self.db, &said)?;
            if parent_said == said {
                dbg!("Malformed history for said: {}", said);
                return Err(vec![format!("Malformed history")]);
            }
            let s = SelfAddressingIdentifier::from_str(&said).unwrap(); // TODO
            let oca_bundle = self.get_oca_bundle(s).unwrap().clone();

            history.push(OCABuildStep {
                parent_said: parent_said.clone().parse().ok(),
                command,
                result: oca_bundle,
            });
            said = parent_said;

            if said.is_empty() {
                break;
            }
        }
        history.reverse();
        Ok(history)
    }

    /// Retrive the ocafile for a given said
    /// If dereference is true, all local references will be dereferenced to SAID
    pub fn get_oca_bundle_ocafile(
        &self,
        said: SelfAddressingIdentifier,
        dereference: bool,
    ) -> Result<String, Vec<String>> {
        let oca_bundle_steps = self.get_oca_bundle_steps(said)?;
        let mut oca_ast = OCAAst::new();
        for step in oca_bundle_steps {
            oca_ast.commands.push(step.command);
        }

        if dereference {
            #[cfg(feature = "local-references")]
            local_references::replace_refn_with_refs(&mut oca_ast, &self.db)
                .map_err(|e| vec![e.to_string()])?;
        }

        Ok(ocafile::generate_from_ast(&oca_ast))
    }

    /// Retrive steps (AST representation) for a given said
    ///
    pub fn get_oca_bundle_ast(
        &self,
        said: SelfAddressingIdentifier,
    ) -> Result<OCAAst, Vec<String>> {
        let oca_bundle_steps = self.get_oca_bundle_steps(said)?;
        let mut oca_ast = OCAAst::new();
        for step in oca_bundle_steps {
            oca_ast.commands.push(step.command);
        }
        Ok(oca_ast)
    }

    pub fn parse_oca_bundle_to_ocafile(
        &self,
        bundle: &OCABundleModel,
    ) -> Result<String, Vec<String>> {
        // Keep in mind that ast to bundle is not a reversible operation This function existin only
        // to support quick conversion from OCA Bundle to OCAFILE in case if someone loose the
        // original OCAFILE normally any modification of the bundle should start with OCAFILE
        let oca_ast = bundle.to_ast();
        Ok(ocafile::generate_from_ast(&oca_ast))
    }
}

/// Retrive OCA Bundle Model from local storage by its SAID
/// # Arguments
/// * `storage` - Data storage to retrive OCA Bundle
/// * `said` - SAID of the OCA Bundle
/// # Return
/// * `Result<OCABundleModel, Vec<String>>` - OCA Bundle Model or vector of errors
// TODO check if possible to replace by get_oca_bundle
pub(crate) fn get_oca_bundle_model(
    storage: &dyn DataStorage,
    said: SelfAddressingIdentifier,
) -> Result<OCABundleModel, Vec<String>> {
    let r = storage
        .get(Namespace::OCABundlesJSON, &said.to_string())
        .map_err(|e| vec![format!("{}", e)])?;
    let oca_bundle_json = String::from_utf8(
        r.ok_or_else(|| vec![format!("No OCA Bundle found for said: {}", said)])?,
    )
    .unwrap();

    let oca_bundle: Result<OCABundleModel, Vec<String>> = serde_json::from_str(&oca_bundle_json)
        .map_err(|e| vec![format!("Failed to parse oca bundle: {}", e)]);

    Ok(oca_bundle.unwrap())
}

/// Retrive OCA Bundle Set (Bundle JSON + Dependencies if specified) Return a JSON String of the bundle and Vec of
/// dependencies (empty if with_dep = false) where there is JSON of each referenced bundle
/// # Arguments
/// * `storage` - Data storage to retrive OCA Bundle
/// * `said` - SAID of the OCA Bundle
/// * `with_dep` - If true, retrive all dependencies of the OCA Bundle, it works recursively fetching all nested references as well
pub(crate) fn get_oca_bundle_set(
    storage: &dyn DataStorage,
    said: SelfAddressingIdentifier,
    with_dep: bool,
    seen: &mut HashSet<SelfAddressingIdentifier>,
) -> Result<BundleWithDependencies, Vec<String>> {
    let r = storage
        .get(Namespace::OCABundlesJSON, &said.to_string())
        .map_err(|e| vec![format!("{}", e)])?;
    let oca_bundle_json = String::from_utf8(
        r.ok_or_else(|| vec![format!("No OCA Bundle found for said: {}", said)])?,
    )
    .unwrap();

    // Retrive ocabundle to extract potential references
    let oca_bundle_model: Result<OCABundleModel, Vec<String>> =
        serde_json::from_str(&oca_bundle_json)
            .map_err(|e| vec![format!("Failed to parse oca bundle: {}", e)]);

    match oca_bundle_model {
        Ok(oca_bundle_model) => {
            let mut dep_bundles = vec![];
            if with_dep {
                for refs in retrive_all_references(oca_bundle_model.clone()) {
                    if seen.insert(refs.clone()) {
                        let bundle_set = get_oca_bundle_set(storage, refs, true, seen)?;
                        dep_bundles.push(bundle_set.bundle);
                        dep_bundles.extend(bundle_set.dependencies);
                    } else {
                        info!("Skipping already seen SAID: {}", refs);
                    }
                }
            }
            let result = BundleWithDependencies {
                bundle: OCABundle::from(oca_bundle_model),
                dependencies: dep_bundles,
            };

            Ok(result)
        }
        Err(e) => Err(e),
    }
}

/// Retrive all existing references from given OCA Bundle
///
/// # Arguments
/// * `said` - SAID of the OCA Bundle
///
/// # Return
/// * `Vec<String>` - Vector of all SAID references
fn retrive_all_references(bundle: OCABundleModel) -> Vec<SelfAddressingIdentifier> {
    let mut refs: Vec<SelfAddressingIdentifier> = vec![];

    for (_, value) in bundle.capture_base.attributes {
        match value {
            ast::NestedAttrType::Reference(RefValue::Said(said)) => {
                refs.push(said);
            }
            // TODO(recursion) handle nested arrays
            ast::NestedAttrType::Array(box_attr_type) => {
                if let ast::NestedAttrType::Reference(RefValue::Said(said)) = &*box_attr_type {
                    refs.push(said.clone());
                }
            }
            _ => {}
        }
    }
    refs
}

#[cfg(test)]
mod test {
    use overlay_file::overlay_registry::OverlayLocalRegistry;

    use super::*;
    use crate::data_storage::InMemoryDataStorage;
    use crate::repositories::SQLiteConfig;

    #[test]
    fn facade_get_ocafile() -> Result<(), Vec<String>> {
        let _ = env_logger::builder().is_test(true).try_init();
        let db = InMemoryDataStorage::new();
        let db_cache = InMemoryDataStorage::new();
        let cache_storage_config = SQLiteConfig::build().unwrap();
        let mut facade = Facade::new(Box::new(db), Box::new(db_cache), cache_storage_config);
        let ocafile_input = r#"
ADD ATTRIBUTE d=Text i=Text passed=Boolean

ADD Overlay META
  language="en"
  description="Entrance credential"
  name="Entrance credential"

ADD Overlay CHARACTER_ENCODING
  attribute_character_encodings
    d="utf-8"
    i="utf-8"
    passed="utf-8"

ADD Overlay CONFORMANCE
  attribute_conformances
    d="M"
    i="M"
    passed="M"

ADD Overlay LABEL
  language="en"
  attribute_labels
    d="Schema digest"
    i="Credential Issuee"
    passed="Passed"

ADD Overlay FORMAT
  attribute_formats
    d="image/jpeg"

ADD Overlay UNIT
  metric_system="SI"
  attribute_units
    i="m"

ADD ATTRIBUTE list=[Text] el=Text

ADD Overlay CARDINALITY
  attribute_cardinalities
    list="1-2"

ADD Overlay ENTRY_CODE
  attribute_entry_codes
    list=refs:ENrf7niTCnz7HD-Ci88rlxHlxkpQ2NIZNNv08fQnXANI
    el=["o1", "o2", "o3"]

ADD Overlay ENTRY
  language="en"
  attribute_entries
    list=refs:ENrf7niTCnz7HD-Ci88rlxHlxkpQ2NIZNNv08fQnXANI
    el
      o1="o1_label"
      o2="o2_label"
      o3="o3_label"
"#
        .to_string();

        let registry = OverlayLocalRegistry::from_dir("../overlay-file/core_overlays").unwrap();
        let oca_bundle = facade
            .build_from_ocafile(ocafile_input, registry.clone())
            .unwrap();
        let ocafile = facade.parse_oca_bundle_to_ocafile(&oca_bundle)?;
        let new_bundle = facade.build_from_ocafile(ocafile, registry);
        match new_bundle {
            Ok(new_bundle) => {
                assert_eq!(oca_bundle.digest, new_bundle.digest);
            }
            Err(e) => {
                println!("{:#?}", e);
                panic!("Faild to load oca bundle");
            }
        }

        Ok(())
    }
}
