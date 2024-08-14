use self::{account::Account, directory::Directory};
use crate::Environment;
use azure_security_keyvault::prelude::{JsonWebKeyType, KeyVaultGetCertificateResponse};
use std::error::Error;

pub type Nonce = String;

pub mod account;
pub mod challenge;
pub mod directory;
pub mod order;
pub mod updated_order;
pub mod util;

#[cfg(debug_assertions)]
pub const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
#[cfg(not(debug_assertions))]
pub const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

pub async fn cert_new(
    domain: &str,
    id: &str,
    env: &Environment,
) -> Result<KeyVaultGetCertificateResponse, Box<dyn Error>> {
    log::info!(
        "Creating certificate for domain: {} with id: {}",
        domain,
        id
    );

    let http_client = reqwest::Client::new();
    let account_key = env.key_client.get("letsencrypt").await?;

    log::info!("Got account key");

    // create csr
    let csr = env
        .certificate_client
        .create(id, format!("CN={}", domain), "Unknown")
        .dns_names(vec![domain.to_string()])
        .kty(JsonWebKeyType::Rsa)
        .key_size(2048)
        .await?;

    log::info!("Created CSR");

    // Get directory
    let dir_infos = Directory::fetch_dir(&http_client, LETS_ENCRYPT_DIRECTORY).await?;

    log::info!("Got directory");

    // Create account and accept terms of service
    let new_acc: Account = dir_infos
        .create_account(&http_client, &account_key, env.account_email.as_ref(), env)
        .await?;

    log::info!("Created account");

    // create certificate order
    let order = new_acc
        .create_new_order(&http_client, &dir_infos.new_order, env, domain, csr.csr)
        .await?;

    log::info!("Created certificate order");

    // fetch the auth challenges
    let challenge = order
        .fetch_auth_challenges(&http_client, &new_acc.account_location, env)
        .await?;

    log::info!("Fetched auth challenges");

    // complete the challenge and save the nonce that's needed for further authentification
    let new_nonce = challenge
        .complete_http_challenge(&http_client, &new_acc.account_location, &account_key, env)
        .await?;

    log::info!("Setup http challenge");

    std::thread::sleep(std::time::Duration::from_secs(10));

    // finalize the order to retrieve location of the final cert
    let updated_order = order
        .finalize_order(&http_client, &new_acc.account_location, new_nonce, env)
        .await?;

    log::info!("Finalized order");

    // retrieve the x5c
    let cert_chain = updated_order
        .download_certificate(&http_client, &new_acc.account_location, env)
        .await?;

    log::info!("Retrieved x5c");

    // merge x5c
    let cert = env.certificate_client.merge(id, vec![cert_chain]).await?;

    log::info!("x5c merged");

    // return
    Ok(cert)
}
