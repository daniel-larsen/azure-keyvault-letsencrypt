use std::fs;
use axum::{extract::Path, http::StatusCode, response::{IntoResponse, Response}};
use tracing::info;
use crate::utils::app_error::AppError;

pub async fn run(Path(token): Path<String>) -> Result<Response, AppError> {

    info!("token found in path {}", token);

    let contents = match fs::read_to_string(token) {
        Ok(contents) => contents,
        Err(error) => {
            info!("file matching token not found");
            info!("{}", error.to_string());
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
    };
    info!("file found matching token");

    Ok((StatusCode::OK, contents).into_response())
}
