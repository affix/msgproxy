//! Shared pieces for the *direct* transports (TCP, WebSocket, UDP).
//!
//! Unlike the chat backends, these have no third party in the middle: the two
//! msgproxy ends talk to each other, so one has to listen and the other has to
//! dial. By convention the exit node listens, because that is the end that sits
//! on a reachable host — but either end can take either role.
//!
//! Nothing here changes the security story: frames are still encrypted and
//! authenticated with the shared passphrase before they hit the socket. A
//! direct transport without `--key` is plaintext on the wire.

use std::time::Duration;

pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// Bind this address and wait for the peer to connect.
    Listen(String),
    /// Dial the peer at this address.
    Connect(String),
}

impl Role {
    /// `listen` wins if both are given; that combination is a misconfiguration
    /// worth rejecting rather than silently picking one.
    pub fn resolve(listen: Option<&str>, connect: Option<&str>, what: &str) -> anyhow::Result<Role> {
        match (listen, connect) {
            (Some(_), Some(_)) => Err(anyhow::anyhow!(
                "{what}: give either a listen address or a connect address, not both"
            )),
            (Some(addr), None) => Ok(Role::Listen(addr.to_string())),
            (None, Some(addr)) => Ok(Role::Connect(addr.to_string())),
            (None, None) => Err(anyhow::anyhow!(
                "{what}: needs a listen address (exit node) or a connect address (client)"
            )),
        }
    }

    pub fn address(&self) -> &str {
        match self {
            Role::Listen(addr) | Role::Connect(addr) => addr,
        }
    }

    pub fn is_listener(&self) -> bool {
        matches!(self, Role::Listen(_))
    }
}

/// Exponential backoff, capped, for reconnect loops.
pub fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_BACKOFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_listen_address() {
        let role = Role::resolve(Some("0.0.0.0:9000"), None, "tcp").unwrap();
        assert_eq!(role, Role::Listen("0.0.0.0:9000".into()));
        assert!(role.is_listener());
        assert_eq!(role.address(), "0.0.0.0:9000");
    }

    #[test]
    fn resolves_a_connect_address() {
        let role = Role::resolve(None, Some("example:9000"), "tcp").unwrap();
        assert_eq!(role, Role::Connect("example:9000".into()));
        assert!(!role.is_listener());
    }

    #[test]
    fn rejects_both_addresses() {
        let err = Role::resolve(Some("a:1"), Some("b:2"), "tcp").unwrap_err().to_string();
        assert!(err.contains("not both"), "got: {err}");
    }

    #[test]
    fn rejects_neither_address() {
        assert!(Role::resolve(None, None, "tcp").is_err());
    }

    #[test]
    fn backoff_grows_and_caps() {
        let mut delay = Duration::from_secs(1);
        for _ in 0..10 {
            delay = next_backoff(delay);
        }
        assert_eq!(delay, MAX_BACKOFF);
    }
}
