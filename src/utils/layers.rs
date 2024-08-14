use axum::{extract::Request, middleware::Next, response::Response};
#[cfg(not(debug_assertions))]
use std::ops::Not;
#[cfg(not(debug_assertions))]
use axum::response::IntoResponse;

pub async fn auth(
    request: Request,
    next: Next,
) -> Response {

    if request.uri().path().contains("/.well-known/acme-challenge/") || 
        request.uri().path().contains("/checkCertificates") || 
        request.uri().path().contains("/healthCheck") 
    {
        return next.run(request).await;
    }


    #[cfg(not(debug_assertions))]
    if request.headers().contains_key("x-ms-client-principal-id").not() {
        // the user is not logged in
        let login_url = format!("/.auth/login/aad?post_login_redirect_url=https://letsencrypt.larsen.farm{}", request.uri().path());
        if request.headers().contains_key("hx-request") {
            // tell htmx to redirect to login page
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("HX-Redirect", login_url.parse().unwrap());
            return (axum::http::StatusCode::UNAUTHORIZED, headers).into_response();
        } else {
            // tell browser to redirect to login page
            return axum::response::Redirect::to(&login_url).into_response();
        }
    }

    next.run(request).await
}
