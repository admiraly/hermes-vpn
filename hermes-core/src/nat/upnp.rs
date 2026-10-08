//! UPnP IGD port mapping — ask the home router to forward a public UDP
//! port to our socket, which makes us directly reachable even behind a
//! NAT that would otherwise defeat hole punching.
//!
//! Best effort by design: many routers ship with UPnP disabled, so every
//! failure is just "no UPnP candidate" to the caller.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use igd_next::aio::tokio::search_gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use tracing::debug;

use crate::error::{HermesError, Result};

/// How long to wait for a gateway to answer SSDP discovery.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(3);
/// Requested mapping lifetime. Routers that reject finite leases are
/// retried with 0 (= indefinite, the only value some IGDv1 boxes accept).
const LEASE_SECS: u32 = 3600;

/// Map `internal_ip:internal_port` (UDP) on the gateway, preferring the
/// same external port. Returns the public `ip:port` peers should use.
///
/// # Errors
/// Fails if no gateway answers, it refuses the mapping, or it reports a
/// non-IPv4 external address.
pub async fn map_udp_port(
    internal_ip: Ipv4Addr,
    internal_port: u16,
    description: &str,
) -> Result<SocketAddrV4> {
    if internal_ip.is_unspecified() || internal_port == 0 {
        return Err(HermesError::Nat(
            "UPnP needs a concrete local address".into(),
        ));
    }
    let gateway = search_gateway(SearchOptions {
        timeout: Some(SEARCH_TIMEOUT),
        ..SearchOptions::default()
    })
    .await
    .map_err(|e| HermesError::Nat(format!("UPnP gateway search: {e}")))?;

    let external_ip = match gateway
        .get_external_ip()
        .await
        .map_err(|e| HermesError::Nat(format!("UPnP external IP: {e}")))?
    {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(HermesError::Nat("UPnP gateway reported IPv6".into())),
    };

    let local = SocketAddr::V4(SocketAddrV4::new(internal_ip, internal_port));
    let attempt = gateway
        .add_port(
            PortMappingProtocol::UDP,
            internal_port,
            local,
            LEASE_SECS,
            description,
        )
        .await;
    if let Err(e) = attempt {
        debug!(?e, "UPnP finite lease refused — retrying indefinite");
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                internal_port,
                local,
                0,
                description,
            )
            .await
            .map_err(|e| HermesError::Nat(format!("UPnP add_port: {e}")))?;
    }
    debug!(%external_ip, port = internal_port, "UPnP mapping created");
    Ok(SocketAddrV4::new(external_ip, internal_port))
}
