use clap::{Parser, Subcommand};
use aegis_nids::{DetectionEngine, EngineConfig, PacketParser, PacketView};

#[derive(Parser)]
#[command(author = "Lazarus Ebi", version = "0.1.0", about = "Aegis Network Intrusion Detection Engine")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Simulate {
        #[arg(short, long, default_value_t = 100)]
        packets: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    let mut engine = DetectionEngine::new(EngineConfig::default());

    match cli.command {
        Commands::Simulate { packets } => {
            println!("🛡️ Starting Aegis NIDS Simulation (evaluating {} packets)...", packets);

            // Construct synthetic ARP Poisoning packet
            let mut arp_packet_normal = vec![0u8; 42];
            arp_packet_normal[12] = 0x08; arp_packet_normal[13] = 0x06; // ETHERTYPE_ARP
            arp_packet_normal[20] = 0x00; arp_packet_normal[21] = 0x02; // Reply
            arp_packet_normal[22..28].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
            arp_packet_normal[28..32].copy_from_slice(&[192, 168, 1, 1]); // Gateway IP

            let mut arp_packet_poison = arp_packet_normal.clone();
            arp_packet_poison[22..28].copy_from_slice(&[0x66, 0x66, 0x66, 0x66, 0x66, 0x66]); // Attacker MAC

            if let Some(parsed) = PacketParser::parse(&arp_packet_normal) {
                let _ = engine.inspect(&parsed);
            }

            println!("🚨 Triggering simulated ARP Poisoning attack...");
            if let Some(parsed) = PacketParser::parse(&arp_packet_poison) {
                let alerts = engine.inspect(&parsed);
                for a in alerts {
                    println!("🚨 [ALERT] [{}] {} | Severity: {:?} | Target: {}", a.rule_id, a.title, a.severity, a.target);
                    println!("   ↳ {}", a.description);
                }
            }

            println!("✅ Simulation completed successfully.");
        }
    }
}
