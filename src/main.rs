use axum::{middleware, http::StatusCode, routing::{get, post}, Router};
use azure_security_keyvault::prelude::*;
use utils::layers::auth;
use std::{collections::HashMap, env::Args, net::SocketAddr, sync::{Arc, RwLock}};
use azure_data_cosmos::prelude::{AuthorizationToken, CosmosClient, DatabaseClient};
use crate::utils::tracing::cosmos_tracing;

mod acme;
mod http;
mod keyvault;
mod timer;
mod utils;

type Environment = Arc<EnvironmentInner>;

#[derive(Debug)]
pub struct EnvironmentInner {
    certificate_client: CertificateClient,
    key_client: KeyClient,
    account_email: String,
    challenge_store: RwLock<HashMap<String, String>>
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port_key = "FUNCTIONS_CUSTOMHANDLER_PORT";
    let port: u16 = match std::env::var(port_key) {
        Ok(val) => val.parse().expect("Custom Handler port is not a number!"),
        Err(_) => 3000,
    };

    let mut args = std::env::args();
    let keyvault_url = args.nth(1).expect("Missing KEYVAULT_URL environment variable.");
    let email = args.next().expect("Missing ACCOUNT_EMAIL environment variable.");

    let keyvault_client = KeyvaultClient::new(&keyvault_url, azure_identity::create_credential()?)?;

    let challenge_store = HashMap::<String, String>::new();

    let environment_inner = EnvironmentInner {
        certificate_client: keyvault_client.certificate_client(),
        key_client: keyvault_client.key_client(),
        account_email: email,
        challenge_store: RwLock::new(challenge_store)
    };

    let environment: Environment = Arc::new(environment_inner);

    // connect to cosmos db for logging (this is optional)
    let database_client = cosmos_logging(args).await;
    let _ = tracing_log::LogTracer::init();

    let app = Router::new()
        .route("/healthCheck", get(StatusCode::OK))
        .route("/checkCertificates", post(timer::check::run))
        .route("/.well-known/acme-challenge/:token", get(http::http_challenge::run).post(http::http_challenge::run))
        .route("/delete", post(http::delete::run))
        .route("/register", get(timer::check::run).post(http::new::run))
        .route("/", get(http::status::run))
        .with_state(Arc::clone(&environment))
        .layer(middleware::from_fn(auth));

    // add tracing if connection to cosmos db was successful
    let app = match database_client {
        Some(db) => app.layer(middleware::from_fn_with_state(db, cosmos_tracing)),
        None => app
    };

    // run our app with hyper
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn cosmos_logging(mut args: Args) -> Option<DatabaseClient> {
    let master_key = args.next()?;
    let authorization_token = AuthorizationToken::primary_key(&master_key).ok()?;
    let cosmos_client = CosmosClient::new("letsencrypt", authorization_token);
    Some(cosmos_client.database_client("letsencrypt"))
}