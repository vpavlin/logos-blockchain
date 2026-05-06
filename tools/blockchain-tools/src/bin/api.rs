use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use lb_common_http_client::{BasicAuthCredentials, CommonHttpClient};
use lb_core::{
    crypto::ZkHash,
    mantle::NoteId,
    sdp::{DeclarationId, DeclarationMessage, Locator, ProviderId, ServiceType},
};
use lb_http_api_common::paths::SDP_POST_DECLARATION;
use lb_key_management_system_keys::keys::{Key, ZkPublicKey};
use lb_libp2p::{
    Multiaddr, PeerId, Protocol,
    ed25519::{self, Keypair},
    identity::PublicKey,
};
use lb_node::config::{OnUnknownKeys, UserConfig, deserialize_config_at_path};
use serde::de::DeserializeOwned;
use url::Url;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        CliCommand::Sdp(command) => command.run().await,
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Logos blockchain HTTP API utility")]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

impl Cli {
    async fn run(self) {
        self.command.run().await
    }
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    Sdp(SdpSubCommand),
}

impl CliCommand {
    async fn run(self) {
        match self {
            CliCommand::Sdp(command) => command.run().await,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SdpSubCommand {
    PostDeclaration(PostDeclarationArgs),
}

impl SdpSubCommand {
    async fn run(self) {
        match self {
            SdpSubCommand::PostDeclaration(args) => post_declaration(args).await,
        }
    }
}

#[derive(Debug, Parser)]
struct PostDeclarationArgs {
    #[arg(long)]
    service_type: ServiceType,

    #[arg(long)]
    locator: Locator,

    #[arg(long)]
    user_config_path: PathBuf,

    #[arg(long)]
    zk_id: ZkPublicKey,

    #[arg(long)]
    locked_note_id: NoteId,

    #[arg(long)]
    node_address: Url,

    #[arg(long)]
    username: Option<String>,

    #[arg(long)]
    password: Option<String>,
}

async fn post_declaration(
    PostDeclarationArgs {
        locator,
        locked_note_id,
        node_address,
        service_type,
        user_config_path,
        zk_id,
        username,
        password,
    }: PostDeclarationArgs,
) {
    let user_config =
        deserialize_config_at_path::<UserConfig>(&user_config_path, OnUnknownKeys::Fail).expect(
            format!(
                "failed to read user config at '{}'",
                user_config_path.display()
            )
            .as_str(),
        );

    let UserConfigValues { provider_id } = extract_values(user_config);

    let declaration = DeclarationMessage {
        locators: vec![locator],
        locked_note_id,
        provider_id,
        service_type,
        zk_id,
    };

    let request_url = node_address
        .join(SDP_POST_DECLARATION.trim_start_matches('/'))
        .expect("Invalid node address provided.");

    let client = {
        let credentials = username.map(|u| BasicAuthCredentials::new(u, password));
        CommonHttpClient::new(credentials)
    };

    let declaration_id: DeclarationId = client
        .post(request_url, &declaration)
        .await
        .inspect_err(|e| {
            eprintln!("Failed to post declaration: {e}");
        })
        .unwrap();

    println!("{declaration_id}");
}

fn extract_values(config: UserConfig) -> UserConfigValues {
    let provider_id = extract_blend_provider_id(&config);
    UserConfigValues { provider_id }
}

fn extract_blend_provider_id(config: &UserConfig) -> ProviderId {
    let blend_secret_key_id = &config.blend.non_ephemeral_signing_key_id;
    let Key::Ed25519(blend_secret_key) = config
        .kms
        .backend
        .keys
        .get(blend_secret_key_id)
        .expect("Failed to find Blend non-ephemeral signing key in user config KMS keys.")
    else {
        panic!("Blend non-ephemeral signing key must be an Ed25519 key.")
    };
    let blend_public_key = blend_secret_key.public_key();
    ProviderId(blend_public_key)
}

struct UserConfigValues {
    provider_id: ProviderId,
}

fn parse_service_type(input: &str) -> Result<ServiceType> {
    match input {
        "BN" => Ok(ServiceType::BlendNetwork),
        _ => bail!("unsupported service_type '{input}', expected 'BN'"),
    }
}

fn api_base_url_from_user_config(config: &UserConfig) -> Result<Url> {
    let listen_address = config.api.backend.listen_address;

    let host_ip = match listen_address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };

    let target = SocketAddr::new(host_ip, listen_address.port());
    Url::parse(&format!("http://{target}")).with_context(|| {
        format!(
            "invalid api.listen_address '{}': cannot build URL",
            listen_address
        )
    })
}
