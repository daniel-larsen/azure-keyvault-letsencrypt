use super::{
    account::Account,
    util::{extract_payload_location_and_nonce, jwk, jws},
    Nonce,
};
use crate::Environment;
use azure_security_keyvault::prelude::KeyVaultKey;
use core::fmt::Debug;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;

/// The directory information that get returned in the first request
/// to the server. Contains information about the urls of the common
/// http endpoints.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub key_change: String,
    #[serde(skip)]
    nonce: Nonce,
}

impl Directory {
    /// Fetches the directory information from a specific server. This is the first request
    /// that's send to the server as it's return value holds information about the endpoints.
    pub async fn fetch_dir(client: &Client, server_url: &str) -> Result<Self, Box<dyn Error>> {
        let result = client.get(server_url).send().await?;
        let mut dir_infos = result.json::<Self>().await?;

        // fetch the new nonce
        let nonce = client
            .head(&dir_infos.new_nonce)
            .send()
            .await?
            .headers()
            .get("replay-nonce")
            .ok_or("The client sent an unacceptable anti-replay nonce")?
            .to_str()?
            .to_owned();

        dir_infos.nonce = nonce;

        Ok(dir_infos)
    }

    /// Creates a new account.
    pub async fn create_account(
        &self,
        client: &Client,
        account_key: &KeyVaultKey,
        email: &str,
        env: &Environment,
    ) -> Result<Account, Box<dyn Error>> {
        let jwk = jwk(account_key)?;
        let header = json!({
            "alg": "RS256",
            "url": self.new_account,
            "jwk": jwk,
            "nonce": self.nonce,
        });

        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", email)]
        });

        let payload = jws(payload, header, env).await?;

        let response = client
            .post(&self.new_account)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send()
            .await?;

        tracing::info!("{response:?}");

        let (location, nonce, mut account): (String, Nonce, Account) =
            extract_payload_location_and_nonce(response).await?;

        account.nonce = nonce;
        account.account_location = location;

        Ok(account)
    }
}
