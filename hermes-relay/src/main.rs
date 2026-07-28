
use hermes_core::crypto::NodeId;
use hermes_core::relay::protocol::{self, RelayPacket};
use hermes_core::room::RoomId;
use hermes_core::tap::DATAGRAM_BUFFER_SIZE;

/// A registration goes stale if not refreshed within this window.
/// Clients re-register every 15 s.
const SESSION_TTL: Duration = Duration::from_secs(60);

/// How often the reaper sweeps stale sessions.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Largest datagram we accept — the client's datagram buffer size, so the
/// relay can never truncate a frame a client could legitimately send.
const MAX_DATAGRAM: usize = DATAGRAM_BUFFER_SIZE;

/// One registered (room, node) endpoint.
struct Session {
    addr: SocketAddr,
    last_seen: Instant,
    /// Highest registration timestamp seen — replay guard.
    last_ts: u64,
}

#[derive(Default)]
struct State {
    /// (room, node) → session.
    sessions: DashMap<(RoomId, NodeId), Session>,
    /// Current source address → (room, node). Lets DATA packets identify
    /// their sender without carrying credentials.
    by_addr: DashMap<SocketAddr, (RoomId, NodeId)>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind = std::env::var("HERMES_RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8788".into());
    let socket = Arc::new(UdpSocket::bind(&bind).await?);
    info!(%bind, "hermes-relay listening");

    let state = Arc::new(State::default());

    // Stale-session reaper.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                ticker.tick().await;