use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use lb_common_http_client::{BasicAuthCredentials, CommonHttpClient};
use lb_core::{
    mantle::NoteId,
    sdp::{DeclarationId, DeclarationMessage, Locator, ProviderId, ServiceType},
};
use lb_http_api_common::paths::SDP_POST_DECLARATION;
use lb_key_management_system_keys::keys::{Key, ZkPublicKey};
use lb_libp2p::Multiaddr;
use lb_node::config::{OnUnknownKeys, UserConfig, deserialize_config_at_path};
use serde::{Deserialize, de::IntoDeserializer as _};
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run().await
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Logos blockchain HTTP API utility")]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

impl Cli {
    async fn run(self) -> Result<()> {
        self.command.run().await
    }
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Service Declaration Protocol commands
    Sdp {
        #[command(subcommand)]
        command: SdpSubCommand,
    },
}

impl CliCommand {
    async fn run(self) -> Result<()> {
        match self {
            Self::Sdp { command } => command.run().await,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SdpSubCommand {
    /// Post a service declaration to the node HTTP API
    PostDeclaration(PostDeclarationArgs),
}

impl SdpSubCommand {
    async fn run(self) -> Result<()> {
        match self {
            Self::PostDeclaration(args) => post_declaration(args).await,
        }
    }
}

#[derive(Debug, Parser)]
struct PostDeclarationArgs {
    #[arg(long)]
    service_type: ServiceType,

    #[arg(long)]
    locator: Multiaddr,

    #[arg(long)]
    user_config_path: PathBuf,

    #[arg(long, value_parser = parse_hex_serde::<ZkPublicKey>)]
    zk_id: ZkPublicKey,

    #[arg(long, value_parser = parse_hex_serde::<NoteId>)]
    locked_note_id: NoteId,

    #[arg(long)]
    node_address: Url,

    #[arg(long)]
    username: Option<String>,

    #[arg(long)]
    password: Option<String>,
}

fn parse_hex_serde<T>(input: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    use serde::de::value::Error;

    T::deserialize(input.into_deserializer())
        .map_err(|e: Error| format!("Failed to parse input HEX string: {e}"))
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
) -> Result<()> {
    let user_config =
        deserialize_config_at_path::<UserConfig>(&user_config_path, OnUnknownKeys::Fail)
            .with_context(|| {
                format!(
                    "failed to read user config at '{}'",
                    user_config_path.display()
                )
            })?;

    let UserConfigValues { provider_id } = extract_values(&user_config);

    let declaration = DeclarationMessage {
        locators: vec![Locator::new(locator)],
        locked_note_id,
        provider_id,
        service_type,
        zk_id,
    };

    let request_url = node_address
        .join(SDP_POST_DECLARATION.trim_start_matches('/'))
        .context("invalid node address provided")?;

    let client = {
        let credentials = username.map(|u| BasicAuthCredentials::new(u, password));
        CommonHttpClient::new(credentials)
    };

    let declaration_id: DeclarationId = client
        .post(request_url, &declaration)
        .await
        .context("failed to post declaration")?;

    println!("{declaration_id}");
    Ok(())
}

struct UserConfigValues {
    provider_id: ProviderId,
}

fn extract_values(config: &UserConfig) -> UserConfigValues {
    let provider_id = extract_blend_provider_id(config);
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
