use std::fs;
use axum::{extract::Path, http::StatusCode, response::{IntoResponse, Response}};
use crate::utils::app_error::AppError;

pub async fn run(Path(token): Path<String>) -> Result<Response, AppError> {

    log::info!("token found in path {}", token);

    let contents = match fs::read_to_string(token) {
        Ok(contents) => contents,
        Err(error) => {
            log::info!("file matching token not found");
            log::info!("{}", error.to_string());
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
    };
    log::info!("file found matching token");

    Ok((StatusCode::OK, contents).into_response())
}
