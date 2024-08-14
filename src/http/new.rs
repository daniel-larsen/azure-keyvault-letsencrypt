use axum::{extract::{Host, State}, http::StatusCode, response::{IntoResponse, Redirect, Response}, Form};
use crate::{acme::cert_new, utils::app_error::AppError, Environment};
use std::collections::HashMap;

pub async fn run(
    State(env): State<Environment>,
    Host(hostname): Host,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let domain = match body.get("domain") {
        Some(domain) => domain,
        None => { return Ok((StatusCode::BAD_REQUEST, "Please add a domain to the query string of the request").into_response()); }
    };

    let cert_name = domain.replace('.', "-");

    // Create new certificate
    cert_new(domain, cert_name.as_str(), &env).await?;

    // Redirect to status page
    let redirect_url = format!("http://{}", hostname);
    Ok(Redirect::to(&redirect_url).into_response())
}
