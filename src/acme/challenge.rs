use super::{
    util::{b64, jwk, jws},
    Nonce,
};
use crate::Environment;
use azure_security_keyvault::prelude::KeyVaultKey;
use core::fmt::Debug;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{error::Error, fs};

/// The current status of the request. The status gets send from
/// the server in every response and shows the progress as well as
/// possible errors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StatusType {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "invalid")]
    Invalid,
}

/// Holds information about a `Challenge` in the `ACME` context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub status: StatusType,
    pub token: String,
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
}

/// Holds information about the authentification options in the `ACME` context.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeAuthorisation {
    pub identifier: serde_json::Value,
    pub status: StatusType,
    pub expires: String,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
    #[serde(skip)]
    pub nonce: Nonce,
}

impl ChallengeAuthorisation {
    /// Completes the http challenge by opening an `http` server which returns the needed token
    /// under the specified path.
    pub async fn complete_http_challenge(
        self,
        client: &Client,
        account_url: &str,
        account_key: &KeyVaultKey,
        env: &Environment,
    ) -> Result<Nonce, Box<dyn Error>> {
        let http_challenge = self
            .challenges
            .into_iter()
            .find(|challenge| challenge.challenge_type == "http-01")
            .ok_or("Currently just http challenges are allowed, so this error is raised if no http challenge is present")?;

        ChallengeAuthorisation::complete_challenge(
            client,
            http_challenge,
            self.nonce,
            account_url,
            account_key,
            env,
        )
        .await
    }

    /// Actually opens the server and kicks of the challenge.
    async fn complete_challenge(
        client: &Client,
        challenge_infos: Challenge,
        nonce: Nonce,
        acc_url: &str,
        account_key: &KeyVaultKey,
        env: &Environment,
    ) -> Result<Nonce, Box<dyn Error>> {
        let thumbprint = jwk(account_key)?;
        let mut hasher = Sha256::new();
        hasher.update(&thumbprint.to_string().into_bytes());
        let thumbprint = hasher.finalize();

        let challenge_content = format!("{}.{}", challenge_infos.token, b64(thumbprint));

        let file_name = format!("./{}.txt", challenge_infos.token);
        fs::write(file_name, challenge_content)?;

        ChallengeAuthorisation::kick_off_http_challenge(
            client,
            challenge_infos.clone(),
            nonce,
            acc_url,
            env,
        )
        .await
    }

    /// Requests the check of the server at the `ACME` server instance.
    async fn kick_off_http_challenge(
        client: &Client,
        challenge_infos: Challenge,
        nonce: Nonce,
        acc_url: &str,
        env: &Environment,
    ) -> Result<Nonce, Box<dyn Error>> {
        let header = json!({
            "alg": "RS256",
            "kid": acc_url,
            "nonce": nonce,
            "url": challenge_infos.url
        });

        let payload = json!({});

        let jws = jws(payload, header, env).await?;

        Ok(client
            .post(&challenge_infos.url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()
            .await?
            .headers()
            .get("replay-nonce")
            .ok_or("Response received didn't match the challenge's requirements")?
            .to_str()?
            .to_owned())
    }
}
