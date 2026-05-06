use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use lb_core::{
    mantle::NoteId,
    sdp::{DeclarationId, DeclarationMessage, Locator, ProviderId, ServiceType},
};
use lb_groth16::{Field as _, Fr};
use lb_http_api_common::paths::SDP_POST_DECLARATION;
use lb_key_management_system_keys::keys::ZkPublicKey;
use logos_blockchain_common_http_client::{CommonHttpClient, Error};
use tokio::{net::TcpListener, task::JoinHandle};
use url::Url;

fn sample_declaration() -> DeclarationMessage {
    DeclarationMessage {
        service_type: ServiceType::BlendNetwork,
        locators: vec![Locator::new(
            "/ip4/127.0.0.1/tcp/9000"
                .parse()
                .expect("multiaddr should parse"),
        )],
        provider_id: ProviderId::try_from([1u8; 32])
            .expect("Ed25519 public key from arbitrary bytes"),
        zk_id: ZkPublicKey::zero(),
        locked_note_id: NoteId(Fr::ZERO),
    }
}

#[derive(Clone, Default)]
struct CapturedBody(Arc<Mutex<Option<DeclarationMessage>>>);

async fn echo_id_handler(
    State(state): State<CapturedBody>,
    Json(body): Json<DeclarationMessage>,
) -> Json<DeclarationId> {
    let id = body.id();
    *state.0.lock().expect("captured-body mutex is not poisoned") = Some(body);
    Json(id)
}

async fn server_error_handler() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
}

async fn spawn_server(router: Router) -> (Url, JoinHandle<()>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        drop(axum::serve(listener, router).await);
    });
    let base_url = Url::parse(&format!("http://{addr}/")).expect("base URL is valid");
    (base_url, handle)
}

#[tokio::test]
async fn post_declaration_round_trip() {
    let captured = CapturedBody::default();
    let router = Router::new()
        .route(SDP_POST_DECLARATION, post(echo_id_handler))
        .with_state(captured.clone());
    let (base_url, server) = spawn_server(router).await;

    let client = CommonHttpClient::new(None);
    let declaration = sample_declaration();
    let returned = client
        .post_declaration(base_url, &declaration)
        .await
        .expect("post_declaration should succeed");

    assert_eq!(returned, declaration.id());

    let received = captured
        .0
        .lock()
        .expect("captured-body mutex is not poisoned")
        .clone()
        .expect("server should have received the request body");
    assert_eq!(received, declaration);

    server.abort();
}

#[tokio::test]
async fn post_declaration_propagates_server_error() {
    let router = Router::new().route(SDP_POST_DECLARATION, post(server_error_handler));
    let (base_url, server) = spawn_server(router).await;

    let client = CommonHttpClient::new(None);
    let result = client
        .post_declaration(base_url, &sample_declaration())
        .await;

    assert!(
        matches!(result, Err(Error::Server(_))),
        "5xx responses must surface as Error::Server, got {result:?}"
    );

    server.abort();
}
