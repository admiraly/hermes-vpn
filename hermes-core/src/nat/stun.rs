//! STUN client — discovering our own public address.
//!
//! A node behind NAT cannot see the address the Internet sees it as. STUN
//! (RFC 5389) solves this with the simplest possible exchange: send a
//! Binding request to a public server, and it replies with the source
//! address the request appeared to come from. That *server-reflexive*
//! address is what we advertise as a candidate, and it is what makes UDP
//! hole punching possible.
//!
//! The query deliberately reuses the engine's shared UDP socket rather
//! than opening its own. NAT mappings are per-socket: an address learned
//! on a throwaway socket would describe a mapping that no longer exists
//! by the time a peer tried to use it.
//!
//! One consequence of sharing that socket is that this function will see
//! whatever else is arriving on it — WireGuard datagrams, relay traffic.
//! It therefore reads in a loop, ignoring anything that isn't a
//! well-formed STUN response from the server we asked, until the budget
//! expires. Non-STUN datagrams that arrive during the query window are
//! discarded; in practice gathering happens before a room's tunnels are
//! carrying traffic.

use std::net::SocketAddr;
use std::time::Duration;

use bytecodec::{DecodeExt, EncodeExt};
use rand::Rng;
use stun_codec::rfc5389::attributes::{MappedAddress, XorMappedAddress};
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::error::{HermesError, Result};

/// Public STUN server used when none is configured.
///
/// Cloudflare's resolver also answers STUN on 3478 and is about as
/// reliably reachable as anything on the Internet. Operators who would
/// rather not depend on it can point the engine at their own.
pub const DEFAULT_STUN_SERVER: &str = "1.1.1.1:3478";

/// How long to wait for a Binding response before giving up.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Ask `server` what address our datagrams appear to come from.
///
/// # Errors
/// Fails if the request cannot be sent, no valid response arrives within
/// the timeout, or the response carries no address attribute.
pub async fn query_reflexive_address(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    let transaction_id = TransactionId::new(rand::thread_rng().gen::<[u8; 12]>());
    let request: Message<Attribute> = Message::new(MessageClass::Request, BINDING, transaction_id);

    let bytes = MessageEncoder::new()
        .encode_into_bytes(request)
        .map_err(|e| HermesError::Nat(format!("encode STUN request: {e}")))?;

    socket.send_to(&bytes, server).await?;
    debug!(%server, "STUN binding request sent");

    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    let mut buf = [0u8; 1024];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(HermesError::Nat(format!("no STUN response from {server}")));
        }

        let (len, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return Err(HermesError::Nat(format!("no STUN response from {server}")));
            }
        };

        // Only the server we asked can answer this question.
        if from != server {
            continue;
        }
        // Anything that isn't a decodable STUN message is other traffic
        // on the shared socket, not an error.
        let Ok(Ok(message)) = MessageDecoder::<Attribute>::new().decode_from_bytes(&buf[..len])
        else {
            continue;
        };
        // Ignore responses to some other request.
        if message.transaction_id() != transaction_id {
            continue;
        }
        if message.class() == MessageClass::ErrorResponse {
            return Err(HermesError::Nat(format!(
                "STUN server {server} returned an error"
            )));
        }

        // XOR-MAPPED-ADDRESS is the modern attribute; MAPPED-ADDRESS is
        // the RFC 3489 spelling some servers still emit. Either answers
        // the question.
        if let Some(addr) = message.get_attribute::<XorMappedAddress>() {
            debug!(reflexive = %addr.address(), "STUN reflexive address learned");
            return Ok(addr.address());
        }
        if let Some(addr) = message.get_attribute::<MappedAddress>() {
            debug!(reflexive = %addr.address(), "STUN reflexive address learned (legacy)");
            return Ok(addr.address());
        }

        return Err(HermesError::Nat(
            "STUN response carried no mapped address".into(),
        ));
    }
}
