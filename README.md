# msgproxy — a SOCKS proxy tunnelled through a chat platform

Proxy arbitrary TCP through a chat channel. The **client** exposes a local
SOCKS5 proxy; the **server** (exit node) makes the real outbound connections.
The chat platform is used only as a dumb, ordered message relay — every byte is
framed, base64-encoded, and posted as a normal chat message.

Seven transports ship today, in two families:

- **Relayed through a chat platform** — a third party carries the messages:
  **IRC** (direct `PRIVMSG` between two nicks), **XMPP** (one-to-one chat
  between two JIDs), **WhatsApp** (Business Cloud API), and **Discord**.
- **Direct between the two ends** — no third party: **TCP**, **WebSocket** and
  **UDP**.

```
 app ──socks5──▶ msgproxy client ──frames as messages──▶ relay ──▶ msgproxy server ──tcp──▶ internet
        127.0.0.1:1080     (IRC / XMPP / WhatsApp / Discord              (exit node)
                             · or TCP / WS / UDP direct)
```

## Why relay through a chat platform?

For an **authorised** red-team or penetration-testing engagement, the hard part
of egress is rarely encryption — it is getting *any* outbound channel at all.
A well-run network doesn't offer one:

- Outbound traffic is forced through a proxy that only permits a small set of
  categories or domains.
- Direct connections to arbitrary hosts and ports are dropped, so a plain
  reverse shell or a bare TCP tunnel never leaves the building.
- Newly-registered or uncategorised domains are blocked outright, which kills
  the usual "stand up a VPS and connect back" approach.
- TLS is intercepted, so the *contents* of a connection are inspected even when
  the destination is allowed.

What is almost always permitted is business messaging. Slack, Teams, WhatsApp,
Discord and XMPP are how staff communicate, so their domains sit on the
allowlist, resolve normally, and carry constant encrypted chatter all day. This
tool treats one of those approved channels as a transport: the SOCKS proxy's
bytes become ordinary-looking chat messages between two accounts. Traffic goes
to a domain the network already trusts, over the platform's own TLS, from a
process doing something the environment expects.

That is the point of the design, and it is worth being precise about what it
demonstrates during an engagement:

- **Egress filtering by destination is not a control.** If the allowlist is
  the only thing standing between an implant and the internet, an allowlisted
  SaaS domain is a working exfiltration path.
- **Data-loss prevention that inspects intercepted TLS still sees nothing
  useful here**, because frames are encrypted end-to-end under a passphrase the
  platform never holds — so the channel also models an insider tunnelling data
  out through a sanctioned app.
- **It gives a realistic finding to remediate**, rather than a theoretical one.

### For the defenders reading this

The same properties that make it useful on an engagement are what make it
detectable, and a report should say so:

- The traffic pattern is wrong for a human. A person sends a few messages a
  minute; a tunnel sends a steady stream of uniform, high-entropy, base64-ish
  messages of near-identical length, continuously, in both directions.
- Volume per account is anomalous — megabytes of "chat" from one account.
- The endpoint story is wrong: a server, a build agent, or a service account has
  no business holding a WhatsApp Business or Discord bot session at all.
- Platform-side logging and DLP see the message *rate and size* even when the
  bodies are opaque, and bot/API credentials are centrally revocable.

Rate limits are the practical brake: see the throughput table at the end. This
is a control channel, not a bulk exfiltration channel.

**Use this only where you have written authorisation**, and within the terms of
service of the platform you relay through — tunnelling arbitrary traffic
generally breaches them, which is itself a finding worth reporting rather than
something to hide.

## How it works

- Each SOCKS connection is a **stream**, multiplexed over one channel by a
  10-byte binary header (`side`, `type`, `stream_id`, `seq`) + payload — see
  `src/frame.rs`.
- Frame types: `SYN` (open, carries host:port), `DATA`, `FIN` (half-close), `RST`.
- `seq` numbers let each side reassemble in order even if the platform reorders
  or parallelises sends (`src/stream.rs`).
- The client stamps frames `C`, the server stamps them `S`, and each side ignores
  its own — so **one Discord bot token can drive both ends**, or use two bots.
- Framing is transport-agnostic. `src/tunnel.rs` carries the send queue, retry,
  pacing, de-duplication and dispatch, so a backend implements only `connect`
  and `send_message` and declares its per-message character limit; the payload
  size per frame is *derived* from that. Both ends must use the **same transport**.

```
src/
  frame.rs       wire format: framing, Fernet encryption, message sizing
  stream.rs      per-stream reassembly, shared by both ends
  tunnel.rs      queueing, retry, pacing, dedup, dispatch
  socks.rs       SOCKS5 front-end        exit.rs   exit node
  transport/
    mod.rs       the Transport trait
    irc.rs  xmpp.rs  whatsapp.rs  discord.rs      relayed
    link.rs  tcp.rs  ws.rs  udp.rs                direct
```

## Build

```bash
cargo build --release
```

## Encryption (all transports)

Pick a shared passphrase and use the **same value on both ends**:

```bash
export MSGPROXY_KEY='some long shared passphrase'     # or pass --key
```

---

## Transport: IRC

The two ends `PRIVMSG` each other's nick **directly** — no channel is joined, so
nothing passes through a room where third parties can read the ciphertext, flood
it, or kick you out. Each end needs the other's nick and nothing else.

On the exit node:

```bash
export MSGPROXY_TRANSPORT=irc
export IRC_HOST='irc.libera.chat'
export IRC_NICK='mpserver'               # us
export IRC_PEER='mpclient'               # them
msgproxy server
```

On your local machine (nicks swapped):

```bash
export MSGPROXY_TRANSPORT=irc
export IRC_HOST='irc.libera.chat'
export IRC_NICK='mpclient'
export IRC_PEER='mpserver'
msgproxy client --port 1080
```

TLS on port 6697 is the default; `--irc-no-tls` drops to 6667, and
`--irc-no-tls-verify` accepts a self-signed cert on a private ircd.

Only PRIVMSGs addressed to us *and* sent by the configured peer are accepted.

### Nicks are the address

Because the peer reaches us by exact nick, **register both nicks with NickServ**
(`--irc-nickserv-password`) on any network where someone else might take them.
If our nick is occupied at connect time we fall back to `nick_` and say so
loudly — the tunnel stays silent until the real nick is free, because the peer
is still addressing the original.

Two related server behaviours are reported rather than swallowed: a peer that
isn't online (`401`), and a peer refusing PMs from unidentified senders — the
`+R` user mode, common on public networks.

### Why IRC is the slow one

- **512 bytes per line, total** — including the `:nick!user@host` prefix the
  *server* prepends when relaying. After framing, encryption and base64 that
  leaves roughly **213 bytes per message** for a typical nick; the exact figure
  is computed at startup and printed, and a shorter peer nick buys a few more.
- **Flood protection** — most networks disconnect a client sustaining faster
  than about one message every two seconds. `--irc-rate` (default `1.0`s) is the
  minimum gap. Lower it only on an ircd you control.

Dropped connections are expected, so the transport reconnects with exponential
backoff; queued frames wait for the link rather than being discarded.

---

## Transport: XMPP

Each end logs in as an ordinary account and messages the other's JID directly,
so it looks like two people chatting. Any server works — a public one, or one
you run.

```bash
export MSGPROXY_TRANSPORT=xmpp
export XMPP_JID='tunnel-server@example.org'      # us
export XMPP_PASSWORD='...'
export XMPP_PEER='tunnel-client@example.org'     # them
msgproxy server
```

The client is the mirror image, with the two JIDs swapped.

Only chat messages from the configured peer are accepted; anything else on the
account is ignored, as are error bounces (which would otherwise echo our own
frames back into the reassembler). Matching is on the **bare** JID, so the peer
can reconnect under a different resource without disturbing the tunnel.
StartTLS and reconnection are handled by `tokio-xmpp`.

Frames are capped at 16 KB per message — comfortably inside the stanza limits
servers impose (ejabberd and Prosody default to 256 KB, but some are far
tighter), leaving a ~12 KB payload.

---

## Direct transports: TCP, WebSocket, UDP

No platform in the middle: the two ends talk to each other. One listens and the
other dials — **conventionally the exit node listens**, since that is the end on
a reachable host — but either end can take either role.

```bash
# exit node
msgproxy server --transport tcp --listen-addr 0.0.0.0:9000

# client
msgproxy client --port 1080 --transport tcp --connect-addr exit.example:9000
```

Swap `--transport` for `ws` or `udp`. WebSocket dials a URL
(`--connect-addr ws://exit.example:9000`) and the listening end speaks plain
WebSocket — terminate TLS at a reverse proxy if you want `wss://`. It exists
because a WebSocket survives paths that only forward HTTP.

These are the fastest transports and the easiest way to exercise the tunnel, but
they give up the whole point of the relayed ones: the traffic goes to *your*
host, on *your* port, and looks like exactly what it is. On an engagement, that
is the thing egress filtering is designed to stop.

### UDP is reliable-ish

The tunnel's reassembler waits for a missing sequence number forever, so one
lost datagram would stall that stream permanently. The UDP transport therefore
adds acknowledge-and-retransmit of its own: each datagram carries a sequence
number, is retransmitted on a timer (400 ms doubling to 8 s, ten attempts) until
the peer acknowledges it, and the sequence number doubles as the tunnel's
de-duplication key so retransmits are dropped rather than replayed.

It is **not** congestion-controlled. It fixes "one lost packet stalls a stream
forever"; it does not make UDP a good idea over a congested path. Datagrams are
sized to fit a 1500-byte MTU, so the payload is only ~740 bytes. Prefer TCP or
WebSocket where you can.

---

## Transport: WhatsApp (Business Cloud API)

Each end is a WhatsApp Business phone number; the two numbers message each
other. Frames go out via the Graph API and come back on a **webhook**, so each
end needs a publicly reachable **HTTPS** URL — the Cloud API has no polling mode.

1. At <https://developers.facebook.com> create an app → add **WhatsApp**. For
   each end note its **phone number ID** (the numeric ID, not the phone number)
   and an **access token**. Use a permanent System User token for anything
   long-lived; the default test token expires in 24h.
2. Expose each end's webhook over HTTPS — a reverse proxy (nginx/Caddy) or a
   tunnel, e.g. `cloudflared tunnel --url http://localhost:8080`.
3. In *WhatsApp → Configuration*, set the **Callback URL** to
   `https://your-host/webhook`, set a **Verify token** of your choosing, and
   subscribe to the **messages** field. Meta calls the URL once to verify, so the
   process must already be running. Copy the app secret from *App settings →
   Basic* to enable signature verification.

```bash
export MSGPROXY_TRANSPORT=whatsapp
export WHATSAPP_TOKEN='EAAG...'
export WHATSAPP_PHONE_ID='111111111111111'      # this end's number ID
export WHATSAPP_PEER='+447700900123'            # the *other* end's number
export WHATSAPP_VERIFY_TOKEN='pick-anything'
export WHATSAPP_APP_SECRET='your-app-secret'    # optional but recommended
msgproxy server --wa-webhook-port 8080
```

The client is the mirror image, with `WHATSAPP_PEER` set to the server's number.

### The 24-hour window

Meta only lets a business send freeform text to a number that has messaged it
within the last 24 hours. Steady tunnel traffic keeps the window open in both
directions, but a cold start won't send: **open it once by messaging each number
from the other** (or by sending an approved template), then start the tunnel. If
sends start failing with an HTTP 400 after a long idle period, the window has
lapsed — re-open it the same way.

Deliveries with a bad `X-Hub-Signature-256` are rejected when an app secret is
set. Without one the endpoint accepts anything that parses — a passphrase still
keeps frames unreadable and unforgeable, but set the secret.

---

## Transport: Discord

1. **Create a bot** at <https://discord.com/developers/applications> → *Bot* →
   copy the token. Under *Privileged Gateway Intents*, enable **MESSAGE CONTENT
   INTENT** (required to read message bodies).
2. **Invite it** to a server with *View Channel*, *Send Messages* and
   *Read Message History*. Pick a channel and copy its **channel ID**
   (Developer Mode → right-click channel → Copy ID).

```bash
export MSGPROXY_TRANSPORT=discord
export DISCORD_TOKEN='your-bot-token'
export DISCORD_CHANNEL_ID='123456789012345678'
msgproxy server           # and, on your local machine:
msgproxy client --port 1080
```

The same token works on both ends, since each side ignores its own frames.

---

## Use it

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me     # shows the server's IP
proxychains4 ssh user@host                                # with socks5 127.0.0.1 1080
```

Browsers: set SOCKS v5 host `127.0.0.1`, port `1080`. Use `socks5h`
(remote DNS) so hostnames resolve at the exit node.

## Tests

```bash
cargo test
```

No account, token or internet access is needed. The mocks stand in for each
platform at the network edge only: a mock ircd that relays PRIVMSG *with the
`:nick!user@host` prefix prepended* (the thing that eats the 512-byte budget), a
stand-in Graph API that turns real `POST /messages` calls into genuine
HMAC-signed webhook deliveries against the real webhook server, and a loopback
sink for Discord, whose gateway can't be stood up locally. The direct transports
mock nothing at all — both ends are real, over a real loopback socket. Framing,
encryption, dispatch, retry, de-duplication and reassembly are the shipping code
throughout.

Every transport with an end-to-end harness runs the same battery — round trip,
multi-frame reassembly, concurrent streams, and never exceeding the message
limit — so those properties are asserted repeatedly, once per transport.

Two known-answer tests in `frame.rs` pin the derived key bytes and decrypt a
token captured from an older build. Round-trip tests cannot catch a change in
the crypto, because both ends change together and still agree with each other
while silently losing compatibility with every deployed peer; these catch it.

Coverage is uneven in one place worth knowing: **XMPP and Discord have no
end-to-end test.** Their libraries' gateways can't be stood up locally, so both
are covered by unit tests over the parts that make the decisions — which
messages are accepted, and how sizing and send failures are classified — plus,
for Discord, a full tunnel over a loopback sink. Neither library's own
connection handling is exercised; that needs a live account.

## Limitations & notes

- **Slow.** Throughput is bounded by the platform's message rate limits and API
  latency. Roughly, fastest to slowest:

  | transport | message limit | payload/frame | pacing |
  |---|---|---|---|
  | TCP       | 64 KB (ours) | ~49 KB | as fast as the socket allows |
  | WebSocket | 64 KB (ours) | ~49 KB | as fast as the socket allows |
  | XMPP      | 16 KB (ours) | ~12 KB | server-dependent; usually generous |
  | WhatsApp  | 4096 chars   | 2997 B | 4 requests in flight, one HTTPS round trip each |
  | Discord   | 2000 chars   | 1429 B | serial, a handful of messages/sec per channel |
  | UDP       | 1100 B (MTU) | ~741 B | 4 in flight, plus acknowledgement round trips |
  | IRC       | 512 B/line   | ~213 B | serial, ~1 message/sec (flood protection) |

  Payload sizes are derived from each transport's message limit, not hardcoded.
  The relayed transports are fine for shells, light browsing, and scripting; not
  for streaming or bulk transfer — least of all over IRC. The direct ones are
  limited only by the network.
- **CONNECT only** — no SOCKS BIND or UDP associate; no proxy auth.
- **Optimistic connect:** the client returns SOCKS success immediately; if the
  exit-node connect fails you'll see a connection reset instead of a SOCKS error.
- **Confidentiality from the platform** is provided by `MSGPROXY_KEY`: whole
  frames (header + payload) are encrypted and authenticated with Fernet
  (AES-128-CBC + HMAC-SHA256), the key derived via PBKDF2-SHA256 (200k iters)
  from your passphrase. The platform then sees only ciphertext — not the data,
  not even the stream metadata. **Without a key, frames are base64 only (no
  privacy).** A wrong passphrase authenticates nothing, so mismatched ends
  simply carry no traffic. The key protects against the platform and channel
  observers, not against a malicious exit node — still tunnel TLS/SSH end-to-end
  for untrusted servers.
- Reassembly assumes every frame eventually arrives; a dropped message stalls
  that one stream. Restart the offending connection if it hangs.

Use this only on infrastructure and networks you are authorised to use, and
within the terms of service of the platform you relay through.
