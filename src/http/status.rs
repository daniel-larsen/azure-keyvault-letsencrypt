use crate::{utils::app_error::AppError, keyvault::cert_name, Environment};
use axum::{extract::State, http::StatusCode, response::{Html, IntoResponse, Response}};
use futures::StreamExt;
use time::format_description;

pub async fn run(
    State(env): State<Environment>,
) -> Result<Response, AppError> {
    let mut table = HTML_START.to_owned()
        + HEAD_START
        + BOOTSTRAP_CSS
        + TITLE
        + HEAD_END
        + BODY_START
        + FORM
        + TABLE_START;

    let certs = env
        .certificate_client
        .list_certificates()
        .into_stream()
        .next()
        .await
        .ok_or("Certificates not found")??
        .value;

    log::info!("{} certificates found", certs.len());

    for cert in certs.iter() {
        let expiry = cert.attributes.expires_on.ok_or("expiry date not found")?;
        let format = format_description::parse("[day] [month repr:short] [year]")?;
        table = table
            + "<tr><td>"
            + cert.id.as_str()
            + "</td><td>"
            + expiry.format(&format)?.as_str()
            + "</td><td>"
            + FORM2
            + cert_name(cert).unwrap().as_str()
            + FORM3
            + "</tr>";
        cert.attributes.expires_on.unwrap().to_string();
    }

    table = table + TABLE_END + BODY_END + HTML_END;

    Ok((StatusCode::OK, Html(table)).into_response())
}


static HTML_START: &str = "<html>";
static HTML_END: &str = "</html>";
static BOOTSTRAP_CSS: &str = "<link href='https://cdn.larsen.farm/bootstrap/5.3/css/bootstrap.min.css' rel='stylesheet'>";
static HEAD_START: &str = "<head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>";
static TITLE: &str = "<title>Let's Encrypt Dashboard</title>";
static HEAD_END: &str = "</head>";
static BODY_START: &str = "<body class='container'>";
static BODY_END: &str = "</body>";
static TABLE_START: &str = "<table class='table'><tr><th>Certificate Id</th><th>Expiry</th><th>Action</th></tr>";
static TABLE_END: &str = "</table>";
static FORM: &str = "<form method='post' action='/register'><label for='domain' class='form-label'>Add New Domain:</label><br><input class='form-control' type='text' id='domain' name='domain'><button type='submit' class='btn btn-primary'>Submit</button></form>";
static FORM2: &str = "<form method='post' action='/delete'><input type='hidden' name='cert_name' value='";
static FORM3: &str = "'><button type='submit' class='btn btn-primary'>Delete</button></form>";