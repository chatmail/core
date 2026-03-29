//! SPKI hash storage.
//!
//! We store hashes of Subject Public Key Info from TLS certificates
//! after successful connection to allow connecting when
//! server certificate expires as long as the key is not changed.

use std::collections::BTreeMap;

use anyhow::Result;
use base64::Engine as _;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::pki_types::SubjectPublicKeyInfoDer;

use crate::sql::Sql;

/// Calculates Subject Public Key Info SHA-256 hash and returns it as base64.
///
/// This is the same format as used in <https://www.rfc-editor.org/rfc/rfc7469>.
/// You can calculate the same hash for any remote host with
/// ```sh
/// openssl s_client -connect "$HOST:993" -servername "$HOST" </dev/null 2>/dev/null |
/// openssl x509 -pubkey -noout |
/// openssl pkey -pubin -outform der |
/// openssl dgst -sha256 -binary |
/// openssl enc -base64
/// ```
pub fn spki_hash(spki: &SubjectPublicKeyInfoDer) -> String {
    let spki_hash = Sha256::digest(spki);
    base64::engine::general_purpose::STANDARD.encode(spki_hash)
}

/// Write-through cache for SPKI hashes.
#[derive(Debug)]
pub struct SpkiHashStore {
    /// Map from hostnames to base64 of SHA-256 hashes.
    pub hash_store: RwLock<BTreeMap<String, String>>,
}

impl SpkiHashStore {
    pub fn new() -> Self {
        Self {
            hash_store: RwLock::new(BTreeMap::new()),
        }
    }

    /// Returns base64 of SPKI hash if we have previously successfully connected to given hostname.
    pub async fn get_spki_hash(&self, hostname: &str, sql: &Sql) -> Result<Option<String>> {
        if let Some(hash) = self.hash_store.read().get(hostname).cloned() {
            return Ok(Some(hash));
        }

        match sql
            .query_row_optional(
                "SELECT spki_hash FROM tls_spki WHERE host=?",
                (hostname,),
                |row| {
                    let spki_hash: String = row.get(0)?;
                    Ok(spki_hash)
                },
            )
            .await?
        {
            Some(hash) => {
                self.hash_store
                    .write()
                    .insert(hostname.to_string(), hash.clone());
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Saves SPKI hash after successful connection.
    pub async fn save_spki(
        &self,
        hostname: &str,
        spki: &SubjectPublicKeyInfoDer<'_>,
        sql: &Sql,
    ) -> Result<()> {
        let hash = spki_hash(spki);
        self.hash_store
            .write()
            .insert(hostname.to_string(), hash.clone());
        sql.execute(
            "INSERT OR REPLACE INTO tls_spki (host, spki_hash) VALUES (?, ?)",
            (hostname, hash),
        )
        .await?;
        Ok(())
    }
}
