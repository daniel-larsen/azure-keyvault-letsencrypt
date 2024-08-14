use axum::{http::StatusCode, extract::{Host, State}, response::{IntoResponse, Redirect, Response}, Form};
use crate::{utils::app_error::AppError, Environment};
use std::collections::HashMap;

pub async fn run(
    State(env): State<Environment>,
    Host(hostname): Host,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let cert_name = match body.get("cert_name") {
        Some(domain) => domain,
        None => { return Ok((StatusCode::BAD_REQUEST, "Please add a domain to the query string of the request").into_response()); }
    };

    env.certificate_client.delete(cert_name).await?;

    // Redirect to status page
    let redirect_url = format!("http://{}", hostname);
    Ok(Redirect::to(&redirect_url).into_response())
}
