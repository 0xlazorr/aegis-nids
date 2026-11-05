# Aegis NIDS 🛡️🦀

A high-performance, real-time **Network Intrusion Detection System (NIDS)** and **DNS Covert Channel Analyzer** written in **Rust**.

Engineered for zero-overhead packet parsing, stateful TCP scan detection, ARP cache spoofing identification, and probabilistic Shannon entropy analysis for DNS data exfiltration detection.

---

## 🏛️ Detection Capabilities

```text
Incoming Raw Frame Stream (AF_PACKET / PCAP)
         │
         ├──► [ Packet Dissector ] (Ethernet -> IPv4 -> TCP/UDP/ARP/DNS)
         │
         ├──► [ Stateful TCP Tracker ] ──► SYN Flood / Horizontal Port Scan Detection
         │
         ├──► [ ARP Spoofing Monitor ] ──► Gratuitous ARP / Duplicate MAC Alerting
         │
         └──► [ DNS Entropy Engine ]   ──► Shannon Entropy Calculation (Exfiltration / Tunneling)
                     │
                     ▼
         [ Security Alert Pipeline ] (Real-time JSON & Terminal Alerts)
```

---

## 🌟 Key Features

- **Pure Rust Zero-Copy Packet Parsing**: Dissects raw Layer 2/3/4 headers without requiring external native C libraries.
- **Shannon Entropy DNS Analyzer**: Identifies covert data exfiltration (e.g. `dnscat2`, `iodine`, encoded base32/base64 subdomains) using mathematical entropy thresholds:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- **Stateful Port Scan & SYN Sweep Detection**: Tracks half-open SYN packets across sliding time windows to detect reconnaissance.
- **ARP Poisoning Detection**: Maintains an active IP-to-MAC binding table to alert on unsolicited gratuitous ARP replies and MAC collisions.
- **High-Throughput Concurrent Pipeline**: Multi-channel event dispatching via Tokio async channels.

---

## 📂 Project Structure

```text
aegis-nids/
├── Cargo.toml             # Dependencies & package configuration
├── src/
│   ├── lib.rs             # Public API exports
│   ├── packet.rs          # Zero-copy Layer 2-4 protocol dissectors
│   ├── entropy.rs         # Shannon entropy calculation engine
│   ├── alert.rs           # Structured alert models & JSON serializers
│   ├── engine.rs          # Stateful anomaly detection & state machines
│   └── main.rs            # CLI engine & synthetic traffic simulator
└── README.md
```

---

## 🚀 Quickstart

### Run Synthetic Attack Detection Simulation:
```bash
cargo run --release -- simulate --packets 50000
```

---

## 📜 License
MIT License • Engineered by [Lazarus Ebi](https://github.com/0xlazorr)
