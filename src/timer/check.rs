use crate::acme::cert_new;
use crate::utils::app_error::AppError;
use crate::keyvault::domain;
use crate::{
    keyvault::{cert_name, get_certs},
    Environment,
};
use azure_security_keyvault::prelude::KeyVaultCertificateBaseIdentifier;
use std::{cmp::Ordering, error::Error};
use time::{Duration, OffsetDateTime};
use axum::{http::StatusCode, extract::State, response::{IntoResponse, Response}};


pub async fn run(State(env): State<Environment>) -> Result<Response, AppError> {
    log::info!("{}", "Checking certificates");

    let certs = match get_certs(&env).await {
        Ok(certs) => certs.value,
        Err(error) => {
            log::info!("{}", error.to_string());
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
    };

    log::info!("{} certificates found", certs.len());

    for cert in certs.iter() {
        let expires_on = cert.attributes.expires_on.ok_or("expiry date not found")?;
        let now = OffsetDateTime::now_utc();
        if expires_on.saturating_sub(Duration::days(30)).cmp(&now) == Ordering::Less {
            log::info!("{} expires in less than 30 days.", cert.id);
            match update_cert(cert, &env).await {
                Ok(_) => log::info!("{}", "New Certificate Issued"),
                Err(error) => {
                    log::info!("An error occurred updating certificate: {error:?}")
                }
            };
        } else {
            log::info!("{} expires in more than 30 days", cert.id);
        }
    }

    Ok(StatusCode::OK.into_response())
}

pub async fn update_cert(
    cert_base: &KeyVaultCertificateBaseIdentifier,
    env: &Environment,
) -> Result<(), Box<dyn Error>> {
    let cert_name = cert_name(cert_base).ok_or("certificate name not found")?;
    let cert = env.certificate_client.get(cert_name.clone()).await?;
    let domain = domain(&cert).ok_or("could not extract domain from subject")?;

    // remove pending operation if exists
    match env.certificate_client.get_operation(&cert_name).await {
        Ok(_) => {
            log::info!("Pending certificate operation exists");
            let _ = env.certificate_client.delete_operation(&cert_name).await?;
            log::info!("Pending certificate operation deleted");
        }
        Err(_) => log::info!("No certificate operation pending"),
    };

    cert_new(domain, &cert_name, env).await?;
    Ok(())
}
