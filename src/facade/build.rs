use super::Facade;
use super::fetch::get_oca_bundle_model;
use crate::data_storage::{DataStorage, Namespace};
#[cfg(feature = "local-references")]
use crate::local_references;
#[cfg(feature = "local-references")]
pub use crate::local_references::References;
use crate::repositories::{
    CaptureBaseCacheRecord, CaptureBaseCacheRepo, OCABundleCacheRecord, OCABundleCacheRepo,
};
#[cfg(feature = "local-references")]
use log::debug;
use log::info;
use oca_ast::ast::{OCAAst, ObjectKind, RefValue, ReferenceAttrType};
use oca_bundle::build::{OCABuild, OCABuildStep};
use oca_bundle::state::oca_bundle::{OCABundle, OCABundleModel};
use oca_dag::build_core_db_model;
use oca_file::ocafile;
use overlay_file::overlay_registry::OverlayLocalRegistry;
use std::str::FromStr;
#[cfg(feature = "local-references")]
use said::SelfAddressingIdentifier;

#[derive(thiserror::Error, Debug, serde::Serialize)]
#[serde(untagged)]
pub enum Error {
    #[error("Validation error")]
    ValidationError(Vec<ValidationError>),
    #[error("Deprecated")]
    Deprecated,
}

#[derive(thiserror::Error, Debug, serde::Serialize)]
#[serde(untagged)]
pub enum ValidationError {
    #[error(transparent)]
    OCAFileParse(#[from] oca_file::ocafile::error::ParseError),
    #[error(transparent)]
    OCABundleBuild(#[from] oca_bundle::build::Error),
    #[error("Error at line {line_number} ({raw_line}): {message}")]
    InvalidCommand {
        #[serde(rename = "ln")]
        line_number: usize,
        #[serde(rename = "c")]
        raw_line: String,
        #[serde(rename = "e")]
        message: String,
    },
    #[cfg(feature = "local-references")]
    #[error("Reference {0} not found")]
    UnknownRefn(String),
    #[error("Local references not enabled")]
    LocalReferencesNotEnabled(),
    #[error("Storage error: {0}")]
    StorageError(String),
}

#[cfg(feature = "local-references")]
impl References for Box<dyn DataStorage> {
    fn find(&self, refn: &str) -> Option<String> {
        self.get(Namespace::OCAReferences, refn)
            .unwrap()
            .map(|said| String::from_utf8(said).unwrap())
    }

    fn save(&mut self, refn: &str, value: String) {
        self.insert(Namespace::OCAReferences, refn, value.to_string().as_bytes())
            .unwrap()
    }
}

#[cfg(feature = "local-references")]
impl References for dyn DataStorage + '_ {
    fn find(&self, refn: &str) -> Option<String> {
        self.get(Namespace::OCAReferences, refn)
            .unwrap()
            .map(|said| String::from_utf8(said).unwrap())
    }

    fn save(&mut self, refn: &str, value: String) {
        self.insert(Namespace::OCAReferences, refn, value.to_string().as_bytes())
            .unwrap()
    }
}

#[cfg(feature = "local-references")]
struct DataStorageReferences<'a>(&'a mut dyn DataStorage);

#[cfg(feature = "local-references")]
impl References for DataStorageReferences<'_> {
    fn find(&self, refn: &str) -> Option<String> {
        self.0
            .get(Namespace::OCAReferences, refn)
            .unwrap()
            .map(|said| String::from_utf8(said).unwrap())
    }

    fn save(&mut self, refn: &str, value: String) {
        self.0
            .insert(Namespace::OCAReferences, refn, value.to_string().as_bytes())
            .unwrap()
    }
}

/// Build an OCABundle from OCAFILE
pub fn build_from_ocafile(
    ocafile: String,
    registry: OverlayLocalRegistry,
) -> Result<OCABundle, Error> {
    let ast = ocafile::parse_from_string(ocafile.clone(), &registry)
        .map_err(|e| Error::ValidationError(vec![ValidationError::OCAFileParse(e)]))?;
    let oca_build = oca_bundle::build::from_ast(None, &ast)
        .map_err(|e| {
            e.iter()
                .map(|e| ValidationError::OCABundleBuild(e.clone()))
                .collect::<Vec<_>>()
        })
        .map_err(Error::ValidationError)?;

    let bundle = OCABundle::from(oca_build.oca_bundle.clone());
    Ok(bundle)
}

pub fn parse_oca_bundle_to_ocafile(bundle: &OCABundleModel) -> String {
    ocafile::generate_from_ast(&bundle.to_ast())
}

impl Facade {
    // TODO this name is misleading, it does not only validate ocafile, it builds
    #[cfg(not(feature = "local-references"))]
    pub fn validate_ocafile(
        &self,
        ocafile: String,
        registry: OverlayLocalRegistry,
    ) -> Result<OCABuild, Vec<ValidationError>> {
        let (base, oca_ast) = Self::parse_and_check_base(self.storage(), ocafile, registry, None)?;
        oca_bundle::build::from_ast(base, &oca_ast).map_err(|e| {
            e.iter()
                .map(|e| ValidationError::OCABundleBuild(e.clone()))
                .collect::<Vec<_>>()
        })
    }

    /// Validate ocafile using internal references for dereferencing `refn`.
    /// Mapping between `refn` -> `said` is saved in facades database, so it can
    /// be dereferenced in other ocafiles later.
    // TODO this name is misleading, it does not only validate ocafile, it builds
    #[cfg(feature = "local-references")]
    pub fn validate_ocafile(
        &mut self,
        ocafile: String,
        registry: OverlayLocalRegistry,
    ) -> Result<OCABuild, Vec<ValidationError>> {
        let storage: &dyn DataStorage = &*self.db_cache;
        let (base, oca_ast) = {
            let refs = DataStorageReferences(self.db.as_mut());
            Self::parse_and_check_base(storage, ocafile, registry, Some(&refs))?
        };
        Self::oca_ast_to_oca_build_with_references(base, oca_ast, &mut self.db)
    }

    /// Validate ocafile using external references for dereferencing `refn`.  It
    /// won't update facade internal database with `refn`-> `said` mapping, so `refn`
    /// can't be dereferenced in ocafiles processed later.
    #[cfg(feature = "local-references")]
    pub fn validate_ocafile_with_external_references<R: References>(
        &self,
        ocafile: String,
        references: &mut R,
        registry: OverlayLocalRegistry,
    ) -> Result<OCABuild, Vec<ValidationError>> {
        let refs: &dyn References = references;
        let (base, oca_ast) =
            Self::parse_and_check_base(self.storage(), ocafile, registry, Some(refs))?;
        Self::oca_ast_to_oca_build_with_references(base, oca_ast, references)
    }

    pub fn build(&mut self, oca_build: &mut OCABuild) -> Result<OCABundleModel, Error> {
        self.build_cache(&oca_build.oca_bundle);
        self.build_meta(&oca_build.oca_bundle);

        oca_build
            .steps
            .iter()
            .for_each(|step| self.build_step(step));

        let _ = self.add_relations(&oca_build.oca_bundle);

        self.build_models(oca_build);

        Ok(oca_build.oca_bundle.clone())
    }

    /// Build an OCABundle from OCAFILE
    pub fn build_from_ocafile(
        &mut self,
        ocafile: String,
        registry: OverlayLocalRegistry,
    ) -> Result<OCABundleModel, Error> {
        let mut oca_build = self
            .validate_ocafile(ocafile, registry)
            .map_err(Error::ValidationError)?;

        self.build(&mut oca_build)
    }

    fn parse_and_check_base(
        storage: &dyn DataStorage,
        ocafile: String,
        registry: OverlayLocalRegistry,
        #[cfg(feature = "local-references")] references: Option<&dyn References>,
        #[cfg(not(feature = "local-references"))] _references: Option<()>,
    ) -> Result<(Option<OCABundleModel>, OCAAst), Vec<ValidationError>> {
        // Parse the OCAFILE into an AST, collecting any parse errors.
        let mut oca_ast = ocafile::parse_from_string(ocafile, &registry).map_err(|e| {
            vec![ValidationError::OCAFileParse(
                oca_file::ocafile::error::ParseError::Custom(e.to_string()),
            )]
        })?;

        // Attempt to determine if the first command is a FROM command that references
        // an existing OCABundle. If so, load that bundle into `base`.
        let mut base: Option<OCABundleModel> = None;

        if let Some(first_command) = oca_ast.commands.first()
            && let (oca_ast::ast::CommandType::From, ObjectKind::OCABundle(content)) = (
                first_command.clone().kind,
                first_command.clone().object_kind,
            )
        {
            let default_command_meta = oca_ast::ast::CommandMeta {
                line_number: 0,
                raw_line: "unknown".to_string(),
            };
            let command_meta = oca_ast
                .commands_meta
                .get(&0)
                .unwrap_or(&default_command_meta);
            let invalid_command = |message: String| {
                Vec::from([ValidationError::InvalidCommand {
                    line_number: command_meta.line_number,
                    raw_line: command_meta.raw_line.clone(),
                    message,
                }])
            };

            match content.said {
                ReferenceAttrType::Reference(refs) => match refs {
                    RefValue::Said(said) => match get_oca_bundle_model(storage, said) {
                        Ok(bundle_model) => {
                            info!("Base OCABundle found: {:?}", bundle_model.digest);
                            base = Some(bundle_model.clone());
                        }
                        Err(e) => {
                            return Err(invalid_command(format!("Failed to load bundle: {:?}", e)));
                        }
                    },
                    RefValue::Name(name) => {
                        #[allow(unused_variables)]
                        let name = name;

                        #[cfg(feature = "local-references")]
                        {
                            match references.and_then(|refs| refs.find(&name)) {
                                Some(said) => match SelfAddressingIdentifier::from_str(&said) {
                                    Ok(said_identifier) => {
                                        match get_oca_bundle_model(storage, said_identifier) {
                                            Ok(bundle_model) => {
                                                info!(
                                                    "Base OCABundle found from refn: {:?}",
                                                    bundle_model.digest
                                                );
                                                base = Some(bundle_model.clone());
                                            }
                                            Err(e) => {
                                                return Err(invalid_command(format!(
                                                    "Failed to load bundle: {:?}",
                                                    e
                                                )));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        return Err(invalid_command(format!(
                                            "Invalid SAID format: {}",
                                            e
                                        )));
                                    }
                                },
                                None => {
                                    return Err(invalid_command(format!(
                                        "Reference {} not found",
                                        name
                                    )));
                                }
                            }
                        }
                        #[cfg(not(feature = "local-references"))]
                        {
                            return Err(vec![ValidationError::LocalReferencesNotEnabled()]);
                        }
                    }
                },
            }
            // Remove the FROM command from the AST as it has been processed.
            let _ = oca_ast.commands.remove(0);
        }

        Ok((base, oca_ast))
    }

    #[cfg(feature = "local-references")]
    fn oca_ast_to_oca_build_with_references<R: References>(
        base: Option<OCABundleModel>,
        mut oca_ast: OCAAst,
        references: &mut R,
    ) -> Result<OCABuild, Vec<ValidationError>> {
        // Dereference (refn -> refs) the AST before it start processing bundle steps, otherwise the SAID would
        // not match.
        local_references::replace_refn_with_refs(&mut oca_ast, references).map_err(|e| vec![e])?;

        let oca_build = oca_bundle::build::from_ast(base, &oca_ast).map_err(|e| {
            e.iter()
                .map(|e| ValidationError::OCABundleBuild(e.clone()))
                .collect::<Vec<_>>()
        })?;

        let schema_name = oca_ast.meta.get("name");
        debug!("Schema name found: {:?}", schema_name);

        if let Some(schema_name) = schema_name {
            debug!("Said of new bundle: {:?}", oca_build.oca_bundle.digest);
            let said = oca_build.oca_bundle.digest.clone().unwrap().to_string();
            references.save(schema_name, said.clone());
        };
        Ok(oca_build)
    }

    fn build_cache(&self, oca_bundle: &OCABundleModel) {
        let oca_bundle_cache_repo = OCABundleCacheRepo::new(self.connection());
        let oca_bundle_cache_record = OCABundleCacheRecord::new(oca_bundle);
        oca_bundle_cache_repo.insert(oca_bundle_cache_record);

        let capture_base_cache_repo = CaptureBaseCacheRepo::new(self.connection());
        let capture_base_cache_record = CaptureBaseCacheRecord::new(&oca_bundle.capture_base);
        capture_base_cache_repo.insert(capture_base_cache_record);
    }

    fn build_step(&mut self, step: &OCABuildStep) {
        let mut input: Vec<u8> = vec![];
        match &step.parent_said {
            Some(said) => {
                input.push(said.to_string().len().try_into().unwrap());
                input.extend(said.to_string().as_bytes());
            }
            None => {
                input.push(0);
            }
        }

        let command_str = serde_json::to_string(&step.command).unwrap();
        input.extend(command_str.as_bytes());
        let _ = self.db.insert(
            Namespace::OCA,
            &format!("oca.{}.operation", step.result.digest.clone().unwrap()),
            &input,
        );

        let _ = self.db_cache.insert(
            Namespace::OCABundlesJSON,
            &step.result.digest.clone().unwrap().to_string(),
            &serde_json::to_string(&step.result).unwrap().into_bytes(),
        );
        self.db_cache
            .insert(
                Namespace::OCAObjectsJSON,
                &step.result.capture_base.digest.clone().unwrap().to_string(),
                &serde_json::to_string(&step.result.capture_base)
                    .unwrap()
                    .into_bytes(),
            )
            .unwrap();
        step.result.overlays.iter().for_each(|overlay| {
            self.db_cache
                .insert(
                    Namespace::OCAObjectsJSON,
                    &overlay.digest.clone().unwrap().to_string(),
                    &serde_json::to_string(&overlay).unwrap().into_bytes(),
                )
                .unwrap();
        });
    }

    fn build_models(&mut self, oca_build: &OCABuild) {
        let result_models = build_core_db_model(oca_build);
        result_models.iter().for_each(|model| {
            if let Some(command_model) = &model.command {
                self.db
                    .insert(
                        Namespace::CoreModel,
                        &format!("core_model.{}", command_model.digest),
                        &command_model.json.clone().into_bytes(),
                    )
                    .unwrap();
            }

            if let Some(capture_base_model) = &model.capture_base {
                let mut input: Vec<u8> = vec![];
                match &capture_base_model.parent {
                    Some(said) => {
                        input.push(said.to_string().len().try_into().unwrap());
                        input.extend(said.to_string().as_bytes());
                    }
                    None => {
                        input.push(0);
                    }
                }

                input.push(
                    capture_base_model
                        .command_digest
                        .to_string()
                        .len()
                        .try_into()
                        .unwrap(),
                );
                input.extend(capture_base_model.command_digest.to_string().as_bytes());

                self.db
                    .insert(
                        Namespace::CoreModel,
                        &format!("core_model.{}", capture_base_model.capture_base_said),
                        &input,
                    )
                    .unwrap();
            }

            if let Some(overlay_model) = &model.overlay {
                let mut input: Vec<u8> = vec![];
                match &overlay_model.parent {
                    Some(said) => {
                        input.push(said.to_string().len().try_into().unwrap());
                        input.extend(said.to_string().as_bytes());
                    }
                    None => {
                        input.push(0);
                    }
                }

                input.push(
                    overlay_model
                        .command_digest
                        .to_string()
                        .len()
                        .try_into()
                        .unwrap(),
                );
                input.extend(overlay_model.command_digest.to_string().as_bytes());

                self.db
                    .insert(
                        Namespace::CoreModel,
                        &format!("core_model.{}", overlay_model.overlay_said),
                        &input,
                    )
                    .unwrap();
            }

            if let Some(oca_bundle_model) = &model.oca_bundle {
                let mut input: Vec<u8> = vec![];
                match &oca_bundle_model.parent {
                    Some(said) => {
                        input.push(said.to_string().len().try_into().unwrap());
                        input.extend(said.to_string().as_bytes());
                    }
                    None => {
                        input.push(0);
                    }
                }

                input.push(
                    oca_bundle_model
                        .capture_base_said
                        .to_string()
                        .len()
                        .try_into()
                        .unwrap(),
                );
                input.extend(oca_bundle_model.capture_base_said.to_string().as_bytes());

                for said in &oca_bundle_model.overlays_said {
                    input.push(said.to_string().len().try_into().unwrap());
                    input.extend(said.to_string().as_bytes());
                }

                self.db
                    .insert(
                        Namespace::CoreModel,
                        &format!("core_model.{}", oca_bundle_model.oca_bundle_said),
                        &input,
                    )
                    .unwrap();
            }
        });
    }
}

#[cfg(all(test, feature = "local-references"))]
mod tests {
    use super::*;
    use crate::data_storage::{DataStorage, Namespace, SledDataStorage, SledDataStorageConfig};
    use crate::repositories::SQLiteConfig;
    use overlay_file::overlay_registry::OverlayLocalRegistry;
    use std::fs;
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_storage_dir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("oca_store_refn_test_{}", nanos));
        path
    }

    #[test]
    fn stores_and_resolves_refn() {
        let _ = env_logger::builder().is_test(true).try_init();
        let storage_dir = temp_storage_dir();
        fs::create_dir_all(&storage_dir).unwrap();

        let storage_config = SledDataStorageConfig::build()
            .path(storage_dir.clone())
            .unwrap();
        let db = SledDataStorage::new().config(storage_config);
        let db_cache = db.clone();
        let cache_storage_config = SQLiteConfig::build().unwrap();
        let mut facade = Facade::new(Box::new(db), Box::new(db_cache), cache_storage_config);

        let registry = OverlayLocalRegistry::from_dir("tests/core_overlays").unwrap();
        let base_ocafile = r#"
-- name=base
ADD ATTRIBUTE name=Text
"#
        .to_string();
        let _ = facade
            .build_from_ocafile(base_ocafile, registry.clone())
            .unwrap();

        let stored = facade
            .storage()
            .get(Namespace::OCAReferences, "base")
            .unwrap();
        assert!(stored.is_some(), "refn should be stored in storage");

        let refn_ocafile = r#"
ADD ATTRIBUTE linked=refn:base
"#
        .to_string();
        let bundle = facade.build_from_ocafile(refn_ocafile, registry).unwrap();

        let stored = stored
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .expect("refn should be stored as utf-8");
        let stored_said = said::SelfAddressingIdentifier::from_str(&stored).unwrap();
        match bundle.capture_base.attributes.get("linked") {
            Some(oca_ast::ast::NestedAttrType::Reference(oca_ast::ast::RefValue::Said(said))) => {
                assert_eq!(said, &stored_said);
            }
            other => panic!("expected linked to resolve to said, got {:?}", other),
        }

        let _ = fs::remove_dir_all(storage_dir);
    }
}
