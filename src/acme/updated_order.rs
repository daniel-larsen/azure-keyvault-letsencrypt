use super::{
    util::{deserialize_to_string, jws},
    Nonce,
};
use crate::Environment;
use core::fmt::Debug;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;

/// Holds information about a finalized order in the `ACME` context.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatedOrder {
    #[serde(deserialize_with = "deserialize_to_string")]
    pub status: String,
    expires: String,
    identifiers: serde_json::Value,
    authorizations: serde_json::Value,
    finalize: String,
    pub certificate: String,
    #[serde(skip)]
    pub nonce: Nonce,
}

impl UpdatedOrder {
    /// Downloads an issued certificate.
    pub async fn download_certificate(
        &self,
        client: &Client,
        account_url: &str,
        env: &Environment,
    ) -> Result<String, Box<dyn Error>> {
        let header = json!({
            "alg": "RS256",
            "url": self.certificate,
            "kid": account_url,
            "nonce": self.nonce,
        });
        let payload = json!("");

        let jws = jws(payload, header, env).await?;

        Ok(client
            .post(&self.certificate)
            .header("Content-Type", "application/jose+json")
            .header("Accept", "application/pem-certificate-chain")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()
            .await?
            .text()
            .await?)
    }
}
