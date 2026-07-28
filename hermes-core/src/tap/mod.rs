impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            name: "Hermes".to_string(),
            mac: VirtualMac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ipv4: std::net::Ipv4Addr::new(10, 42, 0, 1),
            ipv4_prefix: 16,
            mtu: VIRTUAL_MTU as u16,
        }
    }
}

/// Platform-agnostic adapter interface.
#[async_trait]
pub trait VirtualAdapter: Send + Sync {
    /// Read the next packet from the adapter (Ethernet frame or raw IP,
    /// depending on [`Self::mode`]).
    async fn recv_frame(&self) -> Result<BytesMut>;

    /// Write a packet to the adapter. On [`AdapterMode::Ip`] platforms
    /// the caller must supply a raw IP packet; on [`AdapterMode::Ethernet`]
    /// the caller must supply an Ethernet frame.
    async fn send_frame(&self, frame: &[u8]) -> Result<()>;

    /// Tear down the adapter and release OS resources.
    async fn shutdown(&self) -> Result<()>;

    /// The config this adapter was brought up with.
    fn config(&self) -> &AdapterConfig;

    /// Which layer this adapter speaks natively.
    fn mode(&self) -> AdapterMode;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_budget_fits_physical_path() {
        // A full-size app packet, fully encapsulated for the relayed path,
        // must not exceed the physical MTU — otherwise it fragments.
        let on_wire = VIRTUAL_MTU + MAX_ENCAP_OVERHEAD;
        assert!(
            on_wire <= PHYSICAL_MTU,
            "VIRTUAL_MTU {VIRTUAL_MTU} + overhead {MAX_ENCAP_OVERHEAD} = {on_wire} \
             exceeds physical MTU {PHYSICAL_MTU}",
        );
    }

    #[test]
    fn datagram_buffer_holds_largest_datagram() {
        // The biggest thing we ever recv/encapsulate: a relayed frame
        // (everything except the outer UDP/IP headers, which the kernel
        // strips before we see the payload).
        let largest = FRAME_BUFFER_SIZE + FRAMING_HEADER + WIREGUARD_OVERHEAD + RELAY_HEADER;
        assert!(
            largest <= DATAGRAM_BUFFER_SIZE,
            "largest datagram {largest} exceeds buffer {DATAGRAM_BUFFER_SIZE}",
        );
    }
}
