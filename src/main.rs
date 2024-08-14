use axum::{middleware, http::StatusCode, routing::{get, post}, Router};
use azure_security_keyvault::prelude::*;
use utils::layers::auth;
use std::net::SocketAddr;

mod acme;
mod http;
mod keyvault;
mod timer;
mod utils;

#[derive(Debug, Clone)]
pub struct Environment {
    certificate_client: CertificateClient,
    key_client: KeyClient,
    account_email: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port_key = "FUNCTIONS_CUSTOMHANDLER_PORT";
    let port: u16 = match std::env::var(port_key) {
        Ok(val) => val.parse().expect("Custom Handler port is not a number!"),
        Err(_) => 3000,
    };

    let mut args = std::env::args();
    let keyvault_url = args
        .nth(1)
        .expect("Missing KEYVAULT_URL environment variable.");

    let email = args
        .next()
        .expect("Missing ACCOUNT_EMAIL environment variable.");

    let keyvault_client = KeyvaultClient::new(&keyvault_url, azure_identity::create_credential()?)?;

    let environment = Environment {
        certificate_client: keyvault_client.certificate_client(),
        key_client: keyvault_client.key_client(),
        account_email: email,
    };

    let app = Router::new()
        .route("/healthCheck", get(StatusCode::OK))
        .route("/checkCertificates", post(timer::check::run))
        .route("/.well-known/acme-challenge/:token", get(http::http_challenge::run).post(http::http_challenge::run))
        .route("/delete", post(http::delete::run))
        .route("/register", post(http::new::run))
        .route("/", get(http::status::run))
        .with_state(environment)
        .layer(middleware::from_fn(auth));

    // run our app with hyper
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
