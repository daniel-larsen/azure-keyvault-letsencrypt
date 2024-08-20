use axum::{extract::{Path, State}, http::StatusCode, response::{IntoResponse, Response}};
use tracing::info;
use crate::{utils::app_error::AppError, Environment};

pub async fn run(Path(token): Path<String>, State(env): State<Environment>) -> Result<Response, AppError> {

    info!("token found in path {}", token);

    let contents = match env.challenge_store.read().unwrap().get(&token) {
        Some(contents) => contents.to_string(),
        None => {
            info!("file matching token not found");
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
    };
    info!("file found matching token");

    Ok((StatusCode::OK, contents).into_response())
}
