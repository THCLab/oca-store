use oca_bundle::state::oca_bundle::OCABundleModel;

use crate::facade::Connection;

#[derive(Debug)]
pub struct OCABundleCacheRecord {
    pub said: String,
    pub oca_bundle: String,
}

impl OCABundleCacheRecord {
    pub fn new(oca_bundle: &OCABundleModel) -> Self {
        // TODO handle error cases and return meaningful error
        // if ocabundlemodel is not computed it should fail here
        Self {
            said: oca_bundle.digest.clone().unwrap().to_string(),
            oca_bundle: serde_json::to_string(oca_bundle)
                .expect("Failed to serialize OCABundleModel"),
        }
    }
}

#[derive(Debug)]
pub struct AllOCABundleRecord {
    pub cache_record: Option<OCABundleCacheRecord>,
    pub total: usize,
}

pub struct OCABundleCacheRepo {
    connection: Connection,
}

impl OCABundleCacheRepo {
    pub fn new(connection: Connection) -> Self {
        let create_table_query = r#"
        CREATE TABLE IF NOT EXISTS oca_bundle_cache(
            said TEXT PRIMARY KEY,
            oca_bundle TEXT
        )"#;
        connection.execute(create_table_query, ()).unwrap();

        Self { connection }
    }

    pub fn insert(&self, model: OCABundleCacheRecord) {
        let query = r#"
        INSERT INTO oca_bundle_cache(said, oca_bundle)
            VALUES (?1, ?2)"#;
        let _ = self
            .connection
            .execute(query, [&model.said, &model.oca_bundle]);
    }

    pub fn fetch_all(&self, limit: usize, page: usize) -> Vec<AllOCABundleRecord> {
        let offset = (page - 1) * limit;
        let mut results = vec![];
        let query = "
        SELECT results.*, count.total
        FROM
        (
            SELECT COUNT(*) OVER() AS total
            FROM oca_bundle_cache
        ) AS count
        LEFT JOIN
        (
            SELECT *
            FROM oca_bundle_cache
            LIMIT ?1 OFFSET ?2
        ) AS results
        ON true
        GROUP BY said";

        let connection = self.connection.connection.lock().unwrap();
        let mut statement = connection.prepare(query).unwrap();
        let models = statement
            .query_map([limit, offset], |row| {
                let cache_record =
                    row.get::<_, Option<String>>(0)
                        .unwrap()
                        .map(|said| OCABundleCacheRecord {
                            said,
                            oca_bundle: row.get(1).unwrap(),
                        });
                Ok(AllOCABundleRecord {
                    cache_record,
                    total: row.get(2).unwrap(),
                })
            })
            .unwrap();
        models.for_each(|model| results.push(model.unwrap()));
        results
    }
}
