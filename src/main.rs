//! msgproxy — a SOCKS5 proxy tunnelled through a chat platform.

use std::sync::Arc;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use msgproxy::frame::{Codec, SIDE_CLIENT, SIDE_SERVER};
use msgproxy::transport::discord::{DiscordConfig, DiscordTransport};
use msgproxy::transport::irc::{IrcConfig, IrcTransport};
use msgproxy::transport::link::Role;
use msgproxy::transport::tcp::TcpTransport;
use msgproxy::transport::udp::UdpTransport;
use msgproxy::transport::whatsapp::{self, WhatsAppConfig, WhatsAppTransport};
use msgproxy::transport::ws::WsTransport;
use msgproxy::transport::xmpp::{XmppConfig, XmppTransport};
use msgproxy::transport::Transport;
use msgproxy::tunnel::Tunnel;
use msgproxy::{exit, socks};

/// Report every missing option for a transport at once, by flag and env var.
fn require(transport: &str, options: &[(&str, bool)]) -> Result<()> {
    let missing: Vec<&str> = options
        .iter()
        .filter(|(_, missing)| *missing)
        .map(|(name, _)| *name)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{transport} transport needs: {}", missing.join(", "))
    }
}

#[derive(Parser)]
#[command(name = "msgproxy", about = "A SOCKS5 proxy tunnelled through a chat platform")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the local SOCKS5 front-end.
    Client {
        #[arg(long, default_value = "127.0.0.1")]
        listen: String,
        #[arg(long, default_value_t = 1080)]
        port: u16,
        #[command(flatten)]
        transport: TransportArgs,
    },
    /// Run the exit node, which makes the real outbound connections.
    Server {
        #[command(flatten)]
        transport: TransportArgs,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum TransportKind {
    /// Relayed through a chat platform.
    Discord,
    Whatsapp,
    Irc,
    Xmpp,
    /// Straight between the two ends, no third party.
    Tcp,
    Ws,
    Udp,
}

#[derive(Args)]
struct TransportArgs {
    /// Message backend to tunnel over.
    #[arg(long, value_enum, env = "MSGPROXY_TRANSPORT", default_value = "irc")]
    transport: TransportKind,

    /// Shared passphrase; enables frame encryption (must match the other end).
    #[arg(long, env = "MSGPROXY_KEY")]
    key: Option<String>,

    /// Discord bot token.
    #[arg(long, env = "DISCORD_TOKEN")]
    token: Option<String>,

    /// Discord channel ID to relay through.
    #[arg(long, env = "DISCORD_CHANNEL_ID")]
    channel: Option<u64>,

    /// WhatsApp Cloud API access token.
    #[arg(long, env = "WHATSAPP_TOKEN")]
    wa_token: Option<String>,

    /// Our phone number ID (the numeric ID, not the phone number).
    #[arg(long, env = "WHATSAPP_PHONE_ID")]
    wa_phone_id: Option<String>,

    /// The other end's phone number in E.164, e.g. +447700900123.
    #[arg(long, env = "WHATSAPP_PEER")]
    wa_peer: Option<String>,

    /// Token Meta echoes back when verifying the webhook.
    #[arg(long, env = "WHATSAPP_VERIFY_TOKEN")]
    wa_verify_token: Option<String>,

    /// App secret; if set, webhook X-Hub-Signature-256 is verified.
    #[arg(long, env = "WHATSAPP_APP_SECRET")]
    wa_app_secret: Option<String>,

    #[arg(long, env = "WHATSAPP_WEBHOOK_HOST", default_value = "0.0.0.0")]
    wa_webhook_host: String,

    #[arg(long, env = "WHATSAPP_WEBHOOK_PORT", default_value_t = 8080)]
    wa_webhook_port: u16,

    #[arg(long, env = "WHATSAPP_WEBHOOK_PATH", default_value = "/webhook")]
    wa_webhook_path: String,

    #[arg(long, env = "WHATSAPP_API_VERSION", default_value = "v22.0")]
    wa_api_version: String,

    /// Messages in flight.
    #[arg(long, env = "WHATSAPP_CONCURRENCY", default_value_t = 4)]
    wa_concurrency: usize,

    /// IRC server hostname.
    #[arg(long, env = "IRC_HOST")]
    irc_host: Option<String>,

    /// Server port (default: 6697 with TLS, 6667 without).
    #[arg(long, env = "IRC_PORT")]
    irc_port: Option<u16>,

    /// The other end's nickname; frames are PRIVMSG'd straight to it.
    #[arg(long, env = "IRC_PEER")]
    irc_peer: Option<String>,

    /// Our nickname (must differ from the other end's).
    #[arg(long, env = "IRC_NICK")]
    irc_nick: Option<String>,

    #[arg(long, env = "IRC_USER")]
    irc_user: Option<String>,

    #[arg(long, env = "IRC_REALNAME")]
    irc_realname: Option<String>,

    /// Server password (PASS).
    #[arg(long, env = "IRC_PASSWORD")]
    irc_password: Option<String>,

    /// If set, IDENTIFY to NickServ after connecting.
    #[arg(long, env = "IRC_NICKSERV_PASSWORD")]
    irc_nickserv_password: Option<String>,

    /// Connect in the clear (default: TLS).
    #[arg(long)]
    irc_no_tls: bool,

    /// Skip certificate verification (self-signed ircd).
    #[arg(long)]
    irc_no_tls_verify: bool,

    /// Minimum seconds between messages; too low means Excess Flood.
    #[arg(long, env = "IRC_RATE", default_value_t = 1.0)]
    irc_rate: f64,

    /// Our bare JID, e.g. tunnel-client@example.org.
    #[arg(long, env = "XMPP_JID")]
    xmpp_jid: Option<String>,

    #[arg(long, env = "XMPP_PASSWORD")]
    xmpp_password: Option<String>,

    /// The other end's bare JID.
    #[arg(long, env = "XMPP_PEER")]
    xmpp_peer: Option<String>,

    /// Direct transports (tcp/ws/udp): bind here and wait for the peer.
    /// Conventionally the exit node listens.
    #[arg(long, env = "MSGPROXY_LISTEN")]
    listen_addr: Option<String>,

    /// Direct transports (tcp/ws/udp): dial the peer here.
    /// For ws, a URL such as ws://host:9000.
    #[arg(long, env = "MSGPROXY_CONNECT")]
    connect_addr: Option<String>,
}

impl TransportArgs {
    fn codec(&self) -> Arc<Codec> {
        Arc::new(match self.key.as_deref() {
            Some(key) if !key.is_empty() => Codec::from_passphrase(key),
            _ => Codec::plaintext(),
        })
    }

    fn build(&self) -> Result<Arc<dyn Transport>> {
        match self.transport {
            TransportKind::Discord => {
                require(
                    "discord",
                    &[
                        ("--token/DISCORD_TOKEN", self.token.is_none()),
                        ("--channel/DISCORD_CHANNEL_ID", self.channel.is_none()),
                    ],
                )?;
                Ok(Arc::new(DiscordTransport::new(DiscordConfig {
                    token: self.token.clone().unwrap(),
                    channel_id: self.channel.unwrap(),
                })))
            }
            TransportKind::Whatsapp => {
                require(
                    "whatsapp",
                    &[
                        ("--wa-token/WHATSAPP_TOKEN", self.wa_token.is_none()),
                        ("--wa-phone-id/WHATSAPP_PHONE_ID", self.wa_phone_id.is_none()),
                        ("--wa-peer/WHATSAPP_PEER", self.wa_peer.is_none()),
                        (
                            "--wa-verify-token/WHATSAPP_VERIFY_TOKEN",
                            self.wa_verify_token.is_none(),
                        ),
                    ],
                )?;
                Ok(Arc::new(WhatsAppTransport::new(WhatsAppConfig {
                    token: self.wa_token.clone().unwrap(),
                    phone_id: self.wa_phone_id.clone().unwrap(),
                    peer: self.wa_peer.clone().unwrap(),
                    verify_token: self.wa_verify_token.clone().unwrap(),
                    app_secret: self.wa_app_secret.clone(),
                    host: self.wa_webhook_host.clone(),
                    port: self.wa_webhook_port,
                    path: self.wa_webhook_path.clone(),
                    api_version: self.wa_api_version.clone(),
                    api_base: whatsapp::DEFAULT_API_BASE.to_string(),
                    concurrency: self.wa_concurrency,
                })?))
            }
            TransportKind::Irc => {
                require(
                    "irc",
                    &[
                        ("--irc-host/IRC_HOST", self.irc_host.is_none()),
                        ("--irc-peer/IRC_PEER", self.irc_peer.is_none()),
                        ("--irc-nick/IRC_NICK", self.irc_nick.is_none()),
                    ],
                )?;
                let tls = !self.irc_no_tls;
                Ok(Arc::new(IrcTransport::new(IrcConfig {
                    host: self.irc_host.clone().unwrap(),
                    port: self.irc_port.unwrap_or(if tls { 6697 } else { 6667 }),
                    peer: self.irc_peer.clone().unwrap(),
                    nick: self.irc_nick.clone().unwrap(),
                    user: self.irc_user.clone(),
                    realname: self.irc_realname.clone(),
                    password: self.irc_password.clone(),
                    nickserv_password: self.irc_nickserv_password.clone(),
                    tls,
                    tls_verify: !self.irc_no_tls_verify,
                    rate: self.irc_rate,
                })?))
            }
            TransportKind::Xmpp => {
                require(
                    "xmpp",
                    &[
                        ("--xmpp-jid/XMPP_JID", self.xmpp_jid.is_none()),
                        ("--xmpp-password/XMPP_PASSWORD", self.xmpp_password.is_none()),
                        ("--xmpp-peer/XMPP_PEER", self.xmpp_peer.is_none()),
                    ],
                )?;
                Ok(Arc::new(XmppTransport::new(XmppConfig {
                    jid: self.xmpp_jid.clone().unwrap(),
                    password: self.xmpp_password.clone().unwrap(),
                    peer: self.xmpp_peer.clone().unwrap(),
                })?))
            }
            TransportKind::Tcp => Ok(Arc::new(TcpTransport::new(self.role("tcp")?))),
            TransportKind::Ws => Ok(Arc::new(WsTransport::new(self.role("ws")?))),
            TransportKind::Udp => Ok(Arc::new(UdpTransport::new(self.role("udp")?))),
        }
    }

    /// Listen or dial, for the direct transports.
    fn role(&self, what: &str) -> Result<Role> {
        Role::resolve(self.listen_addr.as_deref(), self.connect_addr.as_deref(), what)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Several dependencies can each enable a rustls crypto provider; choose one
    // up front so TLS is deterministic rather than panicking on ambiguity.
    XmppTransport::install_crypto_provider();

    let cli = Cli::parse();
    match cli.command {
        Command::Client { listen, port, transport } => {
            let codec = transport.codec();
            let backend = transport.build()?;
            println!("[client] transport: {}", backend.name());
            println!(
                "[client] frame encryption: {}",
                if codec.is_encrypted() { "ON" } else { "OFF (base64 only)" }
            );
            let (tunnel, frames) = Tunnel::start(backend, codec, SIDE_CLIENT).await?;
            socks::run(&listen, port, tunnel, frames).await
        }
        Command::Server { transport } => {
            let codec = transport.codec();
            let backend = transport.build()?;
            println!("[server] transport: {}", backend.name());
            println!(
                "[server] frame encryption: {}",
                if codec.is_encrypted() { "ON" } else { "OFF (base64 only)" }
            );
            let (tunnel, frames) = Tunnel::start(backend, codec, SIDE_SERVER).await?;
            exit::run(tunnel, frames).await;
            Ok(())
        }
    }
}
