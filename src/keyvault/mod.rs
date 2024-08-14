use crate::{acme::util::b64, Environment};
use azure_security_keyvault::prelude::{
    KeyVaultCertificateBaseIdentifier, KeyVaultGetCertificateResponse,
    KeyVaultGetCertificatesResponse, SignatureAlgorithm,
};
use futures::StreamExt;
use std::error::Error;
use url::Url;

pub fn cert_name(cert: &KeyVaultCertificateBaseIdentifier) -> Option<String> {
    let url = match Url::parse(cert.id.as_str()) {
        Ok(url) => url,
        Err(_) => return None,
    };

    url.path_segments()
        .unwrap()
        .nth(1)
        .map(|name| name.to_string())
}

pub fn domain(cert: &KeyVaultGetCertificateResponse) -> Option<&str> {
    match cert.policy.x509_props.subject.split_once('=') {
        Some(subject) => Some(subject.1),
        None => None,
    }
}

pub async fn get_certs(
    env: &Environment,
) -> Result<KeyVaultGetCertificatesResponse, Box<dyn Error>> {
    Ok(env
        .certificate_client
        .list_certificates()
        .into_stream()
        .next()
        .await
        .unwrap()?)
}

pub async fn sign<V>(env: &Environment, value: V) -> Result<String, Box<dyn Error>>
where
    V: Into<String>,
{
    let result = env
        .key_client
        .sign("letsencrypt", SignatureAlgorithm::RS256, value)
        .await?;

    let signature = b64(result.signature);
    Ok(signature)
}
