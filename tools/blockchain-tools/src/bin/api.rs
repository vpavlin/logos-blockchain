use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use lb_common_http_client::{BasicAuthCredentials, CommonHttpClient};
use lb_core::{
    mantle::NoteId,
    sdp::{DeclarationMessage, Locator, ProviderId, ServiceType},
};
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
    PostBlendDeclaration(PostBlendDeclarationArgs),
}

impl SdpSubCommand {
    async fn run(self) -> Result<()> {
        match self {
            Self::PostBlendDeclaration(args) => post_blend_declaration(args).await,
        }
    }
}

#[derive(Debug, Parser)]
struct PostBlendDeclarationArgs {
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

async fn post_blend_declaration(
    PostBlendDeclarationArgs {
        locator,
        locked_note_id,
        node_address,
        user_config_path,
        zk_id,
        username,
        password,
    }: PostBlendDeclarationArgs,
) -> Result<()> {
    let user_config =
        deserialize_config_at_path::<UserConfig>(&user_config_path, OnUnknownKeys::Fail)
            .with_context(|| {
                format!(
                    "failed to read user config at '{}'",
                    user_config_path.display()
                )
            })?;

    let provider_id = extract_blend_provider_id(&user_config)?;

    let declaration = DeclarationMessage {
        locators: vec![Locator::new(locator)],
        locked_note_id,
        provider_id,
        service_type: ServiceType::BlendNetwork,
        zk_id,
    };

    let client = {
        let credentials = username.map(|u| BasicAuthCredentials::new(u, password));
        CommonHttpClient::new(credentials)
    };

    let declaration_id = client
        .post_declaration(node_address, &declaration)
        .await
        .context("Failed to post declaration")?;

    println!("{declaration_id}");
    Ok(())
}

fn extract_blend_provider_id(config: &UserConfig) -> Result<ProviderId> {
    let key_id = &config.blend.non_ephemeral_signing_key_id;
    let key =
        config.kms.backend.keys.get(key_id).with_context(|| {
            format!("blend non-ephemeral signing key '{key_id}' not found in KMS")
        })?;
    let Key::Ed25519(secret_key) = key else {
        anyhow::bail!("blend non-ephemeral signing key must be Ed25519");
    };
    Ok(ProviderId(secret_key.public_key()))
}
