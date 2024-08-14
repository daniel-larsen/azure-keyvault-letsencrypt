use super::Nonce;
use crate::{keyvault::sign, Environment};
use azure_security_keyvault::prelude::KeyVaultKey;
use base64::Engine;
use reqwest::Response;
use serde::{de::DeserializeOwned, Deserialize, Deserializer};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;

pub fn jwk(account_key: &KeyVaultKey) -> Result<serde_json::Value, Box<dyn Error>> {
    let e = b64(account_key.key.e.as_ref().unwrap());
    let n = b64(account_key.key.n.as_ref().unwrap());

    Ok(json!({
        "e": e,
        "n": n,
        "kty": "RSA",
    }))
}

pub async fn jws(
    payload: serde_json::Value,
    header: serde_json::Value,
    env: &Environment,
) -> Result<serde_json::Value, Box<dyn Error>> {
    // edge case when the payload needs to be empty, e.g. for
    // fetching the challenges or downloading the certificate
    let empty_payload = payload == json!("");

    let payload64 = b64(serde_json::to_string_pretty(&payload)?);
    let header64 = b64(serde_json::to_string_pretty(&header)?);

    let result = match empty_payload {
        true => format!("{}.", header64),
        false => format!("{}.{}", header64, payload64),
    };

    let mut hasher = Sha256::new();
    hasher.update(result);
    let result_hash = hasher.finalize();

    let signature = sign(env, b64(&result_hash[..])).await?;

    Ok(json!({
        "protected": header64,
        "payload": if empty_payload { "" } else { &payload64 },
        "signature": signature
    }))
}

pub const URL_SAFE_ENGINE: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD,
    );

/// Returns the `base64url` encoding of the input.
pub fn b64<T>(to_encode: T) -> String
where
    T: AsRef<[u8]>,
{
    Engine::encode(&URL_SAFE_ENGINE, to_encode, )
}

/// Extracts the payload and `replay-nonce` header field from a given http `Response`.
#[inline]
pub async fn extract_payload_and_nonce<T>(response: Response) -> Result<(Nonce, T), Box<dyn Error>>
where
    T: DeserializeOwned,
{
    let replay_nonce = response
        .headers()
        .get("replay-nonce")
        .ok_or("Response received didn't match the challenge's requirements")?
        .to_str()?
        .to_owned();

    Ok((replay_nonce, response.json().await?))
}

/// Extracts the `location` and `replay-nonce` header field as well as
/// the payload from a given http `Response`.
#[inline]
pub async fn extract_payload_location_and_nonce<T>(
    response: Response,
) -> Result<(String, Nonce, T), Box<dyn Error>>
where
    T: DeserializeOwned,
{
    let replay_nonce = response
        .headers()
        .get("replay-nonce")
        .ok_or("Response received didn't match the challenge's requirements")?
        .to_str()?
        .to_owned();

    let location = response
        .headers()
        .get("location")
        .ok_or("Response received didn't match the challenge's requirements")?
        .to_str()?
        .to_owned();

    Ok((location, replay_nonce, response.json().await?))
}

pub fn deserialize_to_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Number(i64),
        Float(f64),
    }

    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(s) => Ok(s),
        StringOrNumber::Number(i) => Ok(i.to_string()),
        StringOrNumber::Float(f) => Ok(f.to_string()),
    }
}
