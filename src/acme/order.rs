use super::{
    challenge::ChallengeAuthorization,
    updated_order::UpdatedOrder,
    util::{b64, deserialize_to_string, extract_payload_and_nonce, jws},
    Nonce,
};
use crate::Environment;
use core::fmt::Debug;
use base64::{engine, Engine};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;

/// Holds information about an `Order` in the `ACME` context.
#[derive(Serialize, Deserialize, Debug)]
pub struct Order {
    #[serde(deserialize_with = "deserialize_to_string")]
    pub status: String,
    pub expires: String,
    pub identifiers: serde_json::Value,
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(skip)]
    pub nonce: Nonce,
    #[serde(skip)]
    pub csr: String,
}

impl Order {
    /// Fetches the available authorization options from the server for a certain order.
    pub async fn fetch_auth_challenges(
        &self,
        client: &Client,
        account_url: &str,
        env: &Environment,
    ) -> Result<ChallengeAuthorization, Box<dyn Error>> {
        let auth_url = self
            .authorizations
            .first()
            .ok_or("Currently just http challenges are allowed, so this error is raised if no http challenge is present")?
            .to_string();

        let header = json!({
            "alg": "RS256",
            "url": auth_url,
            "kid": account_url,
            "nonce": self.nonce,
        });

        let payload = json!("");

        let jws = jws(payload, header, env).await?;

        let response = client
            .post(&auth_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()
            .await?;

        let (nonce, mut challenge): (Nonce, ChallengeAuthorization) =
            extract_payload_and_nonce(response).await?;

        challenge.nonce = nonce;

        Ok(challenge)
    }

    /// Finalizes an order whose challenge was already done. This returns an `UpdatedOrder` object which
    /// is able to download the issued certificate. This method `panics` if the challenge was not yet completed.
    pub async fn finalize_order(
        self,
        client: &Client,
        account_url: &str,
        new_nonce: Nonce,
        env: &Environment,
    ) -> Result<UpdatedOrder, Box<dyn Error>> {
        let header = json!({
        "alg": "RS256",
        "url": self.finalize,
        "kid": account_url,
        "nonce": new_nonce,
        });

        let csr_string = b64(engine::general_purpose::STANDARD.decode(self.csr)?);

        let payload = json!({ "csr": csr_string });

        let jws = jws(payload, header, env).await?;

        let response = client
            .post(&self.finalize)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()
            .await?;

        let (nonce, mut updated_order): (Nonce, UpdatedOrder) =
            extract_payload_and_nonce(response).await?;

        updated_order.nonce = nonce;

        Ok(updated_order)
    }
}
