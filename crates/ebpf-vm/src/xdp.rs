//! XDP driver for the lab VM: packet parsers, action codes, entry point.
//!
//! [`run_xdp`] installs the packet (which also stages the `xdp_md` context
//! in `MemoryView`), points `r1` at `XDP_MD_BASE`, runs to completion, and
//! maps the exit code to [`XdpAction`]. The `xdp_md` layout (`data` at `+0`,
//! `data_end` at `+4`) is documented on
//! [`memory::XDP_MD_BASE`](crate::memory::XDP_MD_BASE). Parsers are
//! hand-rolled (Ethernet/IPv4 only) for learning value — no packet-parsing
//! dependency.

use std::fmt;
use std::net::Ipv4Addr;

use ebpf_isa::{Insn, Reg};

use crate::maps::MapStore;
use crate::memory::{PACKET_BASE, PacketBuffer, XDP_MD_BASE};
use crate::{RunOutcome, Vm};

/// XDP return-code semantics (kernel values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAction {
    /// `XDP_ABORTED` (0): error, drop with tracepoint.
    Aborted,
    /// `XDP_DROP` (1).
    Drop,
    /// `XDP_PASS` (2).
    Pass,
    /// `XDP_TX` (3).
    Tx,
    /// `XDP_REDIRECT` (4).
    Redirect,
    /// Any other exit code (forward-compat; not an error).
    Unknown(i64),
}

impl XdpAction {
    /// Map a raw `r0` exit code to its action.
    #[must_use]
    pub const fn from_code(code: i64) -> Self {
        match code {
            0 => Self::Aborted,
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Tx,
            4 => Self::Redirect,
            other => Self::Unknown(other),
        }
    }

    /// Raw exit code for this action.
    #[must_use]
    pub const fn code(self) -> i64 {
        match self {
            Self::Aborted => 0,
            Self::Drop => 1,
            Self::Pass => 2,
            Self::Tx => 3,
            Self::Redirect => 4,
            Self::Unknown(c) => c,
        }
    }
}

impl fmt::Display for XdpAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aborted => f.write_str("XDP_ABORTED"),
            Self::Drop => f.write_str("XDP_DROP"),
            Self::Pass => f.write_str("XDP_PASS"),
            Self::Tx => f.write_str("XDP_TX"),
            Self::Redirect => f.write_str("XDP_REDIRECT"),
            Self::Unknown(c) => write!(f, "XDP_UNKNOWN({c})"),
        }
    }
}

/// Parsed Ethernet header (14 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthHeader {
    /// Destination MAC.
    pub dst: [u8; 6],
    /// Source MAC.
    pub src: [u8; 6],
    /// `EtherType` in host order (e.g. `0x0800` = IPv4).
    pub ethertype: u16,
}

/// `EtherType` for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Parse the 14-byte Ethernet header.
///
/// Returns `None` when `bytes` is shorter than one header.
#[must_use]
pub const fn parse_eth(bytes: &[u8]) -> Option<EthHeader> {
    let Some(header) = bytes.first_chunk::<14>() else { return None };
    let dst = [header[0], header[1], header[2], header[3], header[4], header[5]];
    let src = [header[6], header[7], header[8], header[9], header[10], header[11]];
    Some(EthHeader { dst, src, ethertype: u16::from_be_bytes([header[12], header[13]]) })
}

/// Parsed IPv4 header fields (no options).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// Protocol (e.g. 6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Total length in host order.
    pub total_len: u16,
}

/// Parse the IPv4 header at `bytes` (expects the IP header first, not the
/// Ethernet frame — callers skip 14 bytes).
///
/// Checks length (≥ 20), version nibble (`4`), and IHL (≥ 5). Returns `None`
/// on any violation; options themselves are not parsed.
#[must_use]
pub const fn parse_ipv4(bytes: &[u8]) -> Option<Ipv4Header> {
    if bytes.len() < 20 {
        return None;
    }
    if bytes[0] >> 4 != 4 {
        return None;
    }
    if bytes[0] & 0x0f < 5 {
        return None;
    }
    Some(Ipv4Header {
        src: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        protocol: bytes[9],
        total_len: u16::from_be_bytes([bytes[2], bytes[3]]),
    })
}

/// Annotate a packet load with a human-readable suffix (best-effort).
///
/// Returns e.g. `"ethertype=IPv4"` for a half-word load at offset 12 of a
/// frame whose bytes decode that way, else `None`. Never fails: unknown
/// offsets or undecodable bytes simply yield no annotation, so `--trace`
/// output degrades to raw disassembly.
#[must_use]
pub fn annotate_packet_load(packet: &[u8], offset: i64, width: u8) -> Option<&'static str> {
    if width == 2 && offset == 12 {
        let eth = parse_eth(packet)?;
        return match eth.ethertype {
            ETHERTYPE_IPV4 => Some("ethertype=IPv4"),
            _ => Some("ethertype=non-IPv4"),
        };
    }
    if width == 1 && offset == 23 {
        let ip = parse_ipv4(packet.get(14..)?)?;
        return match ip.protocol {
            6 => Some("ip.proto=TCP"),
            17 => Some("ip.proto=UDP"),
            _ => Some("ip.proto=other"),
        };
    }
    None
}

/// Run an XDP program against `packet` to completion.
///
/// Installs the packet (staging `xdp_md`), sets `r1 = XDP_MD_BASE` per the
/// XDP calling convention, and maps the exit code to [`XdpAction`].
///
/// # Errors
///
/// Returns [`VmError`](crate::VmError) when the program faults, hits an
/// unknown helper, or exhausts `max_steps`.
pub fn run_xdp(
    insns: Vec<Insn>,
    packet: &[u8],
    stores: Vec<Option<MapStore>>,
    max_steps: usize,
) -> Result<XdpAction, crate::VmError> {
    let mut vm = if stores.iter().all(Option::is_none) {
        Vm::new(insns)
    } else {
        Vm::new_with_stores(insns, stores)
    };

    vm.memory_mut().set_packet(PacketBuffer::from(packet));
    vm.set_reg(Reg(1), XDP_MD_BASE);
    vm.run(max_steps).map(XdpAction::from_code)
}

/// Outcome of [`run_xdp`] in `run`-compatible form (for tests).
#[must_use]
pub fn xdp_data_addrs(packet_len: usize) -> (i64, i64) {
    (PACKET_BASE, PACKET_BASE.saturating_add(i64::try_from(packet_len).unwrap_or(i64::MAX)))
}

/// Re-export for callers that only need the outcome mapping.
pub use XdpAction as Action;

/// Alias kept for the `run`-style tests: raw outcome → action.
#[must_use]
pub fn action_of(outcome: &RunOutcome) -> Option<XdpAction> {
    outcome.as_ref().ok().copied().map(XdpAction::from_code)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn action_codes_roundtrip() {
        for (code, action) in [
            (0, XdpAction::Aborted),
            (1, XdpAction::Drop),
            (2, XdpAction::Pass),
            (3, XdpAction::Tx),
            (4, XdpAction::Redirect),
        ] {
            assert_eq!(XdpAction::from_code(code), action);
            assert_eq!(action.code(), code);
        }
        assert_eq!(XdpAction::from_code(99), XdpAction::Unknown(99));
        assert_eq!(XdpAction::Unknown(-7).code(), -7);
    }

    #[test]
    fn action_display() {
        assert_eq!(XdpAction::Pass.to_string(), "XDP_PASS");
        assert_eq!(XdpAction::Drop.to_string(), "XDP_DROP");
        assert_eq!(XdpAction::Unknown(9).to_string(), "XDP_UNKNOWN(9)");
    }

    #[test]
    fn eth_parses_and_rejects_short() {
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;
        let eth = parse_eth(&frame).unwrap();
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert!(parse_eth(&frame[..13]).is_none());
    }

    #[test]
    fn ipv4_parses_and_rejects_bad_version() {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6;
        let header = parse_ipv4(&ip).unwrap();
        assert_eq!(header.protocol, 6);
        ip[0] = 0x65;
        assert!(parse_ipv4(&ip).is_none());
        assert!(parse_ipv4(&ip[..19]).is_none());
    }

    #[test]
    fn annotate_ethertype_and_proto() {
        let mut pkt = vec![0u8; 34];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        pkt[14] = 0x45;
        pkt[14 + 9] = 6;
        assert_eq!(annotate_packet_load(&pkt, 12, 2), Some("ethertype=IPv4"));
        assert_eq!(annotate_packet_load(&pkt, 23, 1), Some("ip.proto=TCP"));
        assert_eq!(annotate_packet_load(&pkt, 0, 4), None);
        assert_eq!(annotate_packet_load(&pkt[..10], 12, 2), None);
    }

    #[test]
    fn run_xdp_pass_and_oob() {
        use ebpf_isa::RawInsn;
        use ebpf_isa::decode::decode_program;
        const fn w(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
            RawInsn { opcode, regs: (src << 4) | dst, offset: off, imm }.to_bytes()
        }
        // mov64 r0, 2; exit
        let prog = [w(0xb7, 0, 0, 0, 2), w(0x95, 0, 0, 0, 0)];
        let bytes: Vec<u8> = prog.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).unwrap();
        let pkt = vec![0u8; 64];
        assert_eq!(run_xdp(insns, &pkt, Vec::new(), 10_000).unwrap(), XdpAction::Pass);
        // ldxw r0, [r1+0] is a ctx load (data pointer), not OOB.
        let prog = [w(0x61, 0, 1, 0, 0), w(0x95, 0, 0, 0, 0)];
        let bytes: Vec<u8> = prog.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).unwrap();
        assert!(run_xdp(insns, &pkt, Vec::new(), 10_000).is_ok());
    }
}
