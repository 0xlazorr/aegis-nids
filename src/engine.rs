use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Instant;
use crate::alert::{SecurityAlert, Severity};
use crate::entropy::shannon_entropy;
use crate::packet::{PacketView, TransportHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait,
    Closed,
    Reset,
}

#[derive(Debug, Clone)]
pub struct TcpConnectionStateMachine {
    pub state: TcpState,
    pub last_seen: Instant,
    pub syn_count: u32,
}

impl Default for TcpConnectionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpConnectionStateMachine {
    pub fn new() -> Self {
        Self {
            state: TcpState::Listen,
            last_seen: Instant::now(),
            syn_count: 0,
        }
    }

    pub fn transition(&mut self, syn: bool, ack: bool, fin: bool, rst: bool) -> TcpState {
        self.last_seen = Instant::now();
        if rst {
            self.state = TcpState::Reset;
            return self.state;
        }

        match self.state {
            TcpState::Listen => {
                if syn && !ack {
                    self.syn_count += 1;
                    self.state = TcpState::SynReceived;
                }
            }
            TcpState::SynReceived => {
                if ack && !syn {
                    self.state = TcpState::Established;
                } else if syn && !ack {
                    self.syn_count += 1;
                } else if fin {
                    self.state = TcpState::FinWait;
                }
            }
            TcpState::Established => {
                if fin {
                    self.state = TcpState::FinWait;
                }
            }
            TcpState::FinWait => {
                if ack || fin {
                    self.state = TcpState::Closed;
                }
            }
            TcpState::Closed | TcpState::Reset => {
                if syn && !ack {
                    self.syn_count = 1;
                    self.state = TcpState::SynReceived;
                }
            }
            TcpState::SynSent => {
                if syn && ack {
                    self.state = TcpState::Established;
                }
            }
        }
        self.state
    }
}

pub struct EngineConfig {
    pub scan_threshold_ports: usize,
    pub scan_window_secs: u64,
    pub dns_entropy_threshold: f64,
    pub max_tracked_hosts: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            scan_threshold_ports: 15,
            scan_window_secs: 5,
            dns_entropy_threshold: 4.15,
            max_tracked_hosts: 10_000,
        }
    }
}

pub struct DetectionEngine {
    config: EngineConfig,
    arp_table: HashMap<Ipv4Addr, [u8; 6]>,
    syn_tracker: HashMap<Ipv4Addr, (Instant, HashSet<u16>)>,
    tcp_sessions: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), TcpConnectionStateMachine>,
}

impl DetectionEngine {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            arp_table: HashMap::new(),
            syn_tracker: HashMap::new(),
            tcp_sessions: HashMap::new(),
        }
    }

    /// Prunes stale connections and hosts to prevent memory leaks over time
    fn prune_stale_records(&mut self) {
        let window = self.config.scan_window_secs;
        self.syn_tracker.retain(|_, (seen, _)| seen.elapsed().as_secs() <= window);
        self.tcp_sessions.retain(|_, session| {
            session.last_seen.elapsed().as_secs() <= 60 && session.state != TcpState::Closed
        });
        if self.arp_table.len() > self.config.max_tracked_hosts {
            self.arp_table.clear();
        }
    }

    pub fn inspect(&mut self, packet: &PacketView) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        self.prune_stale_records();

        match packet {
            PacketView::Arp { arp, .. } => {
                // Rule 1: ARP Poisoning / Spoofing detection
                if let Some(existing_mac) = self.arp_table.get(&arp.sender_ip) {
                    if *existing_mac != arp.sender_mac {
                        alerts.push(SecurityAlert::new(
                            "SEC-ARP-001",
                            "ARP Spoofing / Poisoning Detected",
                            Severity::Critical,
                            &format!("{:?}", arp.sender_ip),
                            &format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", arp.sender_mac[0], arp.sender_mac[1], arp.sender_mac[2], arp.sender_mac[3], arp.sender_mac[4], arp.sender_mac[5]),
                            &format!("IP address {:?} changed hardware address binding from old MAC to new MAC", arp.sender_ip),
                        ));
                    }
                }
                self.arp_table.insert(arp.sender_ip, arp.sender_mac);
            }
            PacketView::Ipv4 { ip, transport, payload, .. } => {
                match transport {
                    TransportHeader::Tcp(tcp) => {
                        // Explicit TCP Connection State Machine tracking
                        let flow_key = (ip.src_ip, tcp.src_port, ip.dst_ip, tcp.dst_port);
                        let session = self.tcp_sessions.entry(flow_key).or_default();
                        let new_state = session.transition(tcp.syn, tcp.ack, tcp.fin, tcp.rst);

                        // Rule 2: Half-Open Port Scan / SYN Sweep
                        if new_state == TcpState::SynReceived {
                            let entry = self.syn_tracker.entry(ip.src_ip).or_insert_with(|| (Instant::now(), HashSet::new()));
                            if entry.0.elapsed().as_secs() > self.config.scan_window_secs {
                                *entry = (Instant::now(), HashSet::new());
                            }
                            entry.1.insert(tcp.dst_port);

                            if entry.1.len() >= self.config.scan_threshold_ports {
                                alerts.push(SecurityAlert::new(
                                    "SEC-SCAN-002",
                                    "TCP Port Sweep / Half-Open SYN Scan",
                                    Severity::High,
                                    &ip.src_ip.to_string(),
                                    &ip.dst_ip.to_string(),
                                    &format!("Host probed {} unique destination ports within {}s window", entry.1.len(), self.config.scan_window_secs),
                                ));
                                entry.1.clear(); // Reset to avoid spamming alerts
                            }
                        }
                    }
                    TransportHeader::Udp(udp) => {
                        // Rule 3: DNS Tunneling & Covert Channel Detection (port 53)
                        if udp.dst_port == 53 || udp.src_port == 53 {
                            if let Ok(dns_text) = std::str::from_utf8(payload) {
                                let entropy = shannon_entropy(dns_text);
                                if entropy >= self.config.dns_entropy_threshold && dns_text.len() > 30 {
                                    alerts.push(SecurityAlert::new(
                                        "SEC-DNS-003",
                                        "DNS Covert Channel / Data Exfiltration",
                                        Severity::Critical,
                                        &ip.src_ip.to_string(),
                                        &ip.dst_ip.to_string(),
                                        &format!("High Shannon entropy detected in DNS query payload (entropy={:.2}, len={})", entropy, dns_text.len()),
                                    ));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        alerts
    }
}
