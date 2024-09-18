use super::{
    order::Order,
    util::{deserialize_to_string, extract_payload_and_nonce, jws},
    Nonce,
};
use crate::Environment;
use core::fmt::Debug;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;

/// A struct that holds information about an `Account` in the `ACME` context.
#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    #[serde(deserialize_with = "deserialize_to_string")]
    pub status: String,
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    pub orders: Option<Vec<String>>,
    #[serde(skip)]
    pub nonce: Nonce,
    #[serde(skip)]
    pub account_location: String,
}

impl Account {
    /// Creates a new order for issuing a dns certificate for a certain domain.
    pub async fn create_new_order<C>(
        &self,
        client: &Client,
        new_order_url: &str,
        env: &Environment,
        domain: &str,
        csr: C,
    ) -> Result<Order, Box<dyn Error>>
    where
        C: Into<String>,
    {
        let header = json!({
            "alg": "RS256",
            "url": new_order_url,
            "kid": self.account_location,
            "nonce": self.nonce,
        });

        let payload = json!({
            "identifiers": [
                { "type": "dns", "value": domain }
            ],
        });

        let payload = jws(payload, header, env).await?;

        let response = client
            .post(new_order_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send()
            .await?;

        tracing::info!("{response:?}");

        let (nonce, mut order): (Nonce, Order) = extract_payload_and_nonce(response).await?;
        order.nonce = nonce;
        order.csr = csr.into();

        Ok(order)
    }
}
