//! UPnP-IGD port mapping — asking the local router to forward a port.
//!
//! When the router cooperates, this is the best possible outcome for a
//! peer-to-peer room: the mapping is explicit and stable, so peers reach
//! us directly without depending on the timing games hole punching needs.
//! When it doesn't — most corporate networks, most mobile carriers, and
//! any router with UPnP switched off — the whole thing is skipped and
//! traversal falls back to STUN plus hole punching, or to a relay.
//!
//! Every failure here is expected and non-fatal. Callers log the error at
//! debug level and carry on with whatever other candidates they gathered.
//!
//! `igd-next`'s discovery and SOAP calls are synchronous, so the work runs
//! on a blocking thread rather than stalling the async runtime — gateway
//! discovery in particular waits on a multicast response and can take a
//! couple of seconds on a network with no IGD at all.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use igd_next::{PortMappingProtocol, SearchOptions};
use tracing::debug;

use crate::error::{HermesError, Result};

/// How long a mapping is requested for, in seconds.
///
/// Routers vary in whether they honour lease durations at all, and a
/// lease that expires mid-session is worse than one that leaks. Zero
/// requests an indefinite mapping, which is what most IGD implementations
/// do in practice regardless of what you ask for.
const LEASE_SECONDS: u32 = 0;

/// How long to wait for a gateway to answer discovery.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Ask the local IGD to map an external UDP port to `internal_ip:internal_port`.
///
/// Returns the external address the mapping is reachable at.
///
/// # Errors
/// Fails if no gateway is discovered, the gateway refuses the mapping, or
/// its external address cannot be read. All of these are ordinary
/// conditions on networks without working UPnP.
pub async fn map_udp_port(
    internal_ip: Ipv4Addr,
    internal_port: u16,
    description: &str,
) -> Result<SocketAddrV4> {
    let description = description.to_string();

    tokio::task::spawn_blocking(move || {
        let options = SearchOptions {
            timeout: Some(SEARCH_TIMEOUT),
            ..SearchOptions::default()
        };

        let gateway = igd_next::search_gateway(options)
            .map_err(|e| HermesError::Nat(format!("no UPnP gateway: {e}")))?;

        let local = SocketAddr::V4(SocketAddrV4::new(internal_ip, internal_port));

        // add_any_port lets the router pick a free external port, which
        // avoids failing outright when the port we'd prefer is already
        // mapped by another device.
        let external_port = gateway
            .add_any_port(PortMappingProtocol::UDP, local, LEASE_SECONDS, &description)
            .map_err(|e| HermesError::Nat(format!("UPnP mapping refused: {e}")))?;

        let external_ip = gateway
            .get_external_ip()
            .map_err(|e| HermesError::Nat(format!("UPnP external IP unavailable: {e}")))?;

        let external_v4 = match external_ip {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(v6) => {
                return Err(HermesError::Nat(format!(
                    "UPnP gateway reported an IPv6 external address ({v6}); \
                     Hermes candidates are IPv4"
                )));
            }
        };

        let mapped = SocketAddrV4::new(external_v4, external_port);
        debug!(%mapped, %local, "UPnP mapping established");
        Ok(mapped)
    })
    .await
    .map_err(|e| HermesError::Nat(format!("UPnP task panicked: {e}")))?
}
