use axum::{extract::{Request, State}, middleware::Next, response::Response};
use azure_data_cosmos::prelude::DatabaseClient;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::Layer;

pub async fn cosmos_tracing(
    env: State<DatabaseClient>,
    request: Request,
    next: Next,
) -> Response {
    // setup tracing subscriber
    let events = CustomLayer::new(tracing::Level::INFO);
    let subscriber = tracing_subscriber::registry().with(events.clone());

    let path = match request.uri().path_and_query() {
        Some(pq) => pq.to_string(),
        None => String::from("/")
    };
    let method = request.method().to_string();

    // run handler
    let response = next.run(request).with_subscriber(subscriber).await;

    // saving traces to db
    let collection = env.collection_client("traces");

    let traces = LogMessage {
        id: Uuid::new_v4(),
        time: OffsetDateTime::now_utc(),
        method,
        path,
        status: response.status().as_u16(),
        key: OffsetDateTime::now_utc().unix_timestamp() / 60, // partitioned by minutes
        traces: events.get()
    };

    let _ = collection.create_document::<LogMessage>(traces).await.unwrap();

    response // return response
}

#[derive(Serialize)]
pub struct LogMessage {
    pub traces: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    pub method: String,
    pub path: String,
    pub key: i64,
    pub id: Uuid,
    pub status: u16
}

impl azure_data_cosmos::CosmosEntity for LogMessage {
    type Entity = i64;

    fn partition_key(&self) -> Self::Entity {
        self.key
    }
}

#[derive(Clone)]
pub struct CustomLayer {
    events: Arc<Mutex<Vec<String>>>,
    level: Level,
}

impl CustomLayer {
    pub fn new(level: Level) -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            level,
        }
    }

    pub fn get(&self) -> Vec<String> {
        self.events.lock().unwrap().to_vec()
    }
}

impl<S> Layer<S> for CustomLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = CustomVisitor::new();
        event.record(&mut visitor);

        if *event.metadata().level() <= self.level {
            self.events.lock().unwrap().push(format!(
                "{} {:?} {}",
                event.metadata().level(),
                visitor.0,
                event.metadata().name()
            ));
        }
    }
}

struct CustomVisitor(Vec<String>);

impl CustomVisitor {
    fn new() -> Self {
        Self { 0: Vec::new() }
    }
}

impl<'a> tracing::field::Visit for CustomVisitor {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.0.push(format!("{}: {} ", field.name(), value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.push(format!("{}: {} ", field.name(), value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.push(format!("{}: {} ", field.name(), value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0.push(format!("{}: {} ", field.name(), value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push(format!("{}: {} ", field.name(), value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.0.push(format!("{}: {} ", field.name(), value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push(format!("{}: {:?} ", field.name(), value));
    }
}
