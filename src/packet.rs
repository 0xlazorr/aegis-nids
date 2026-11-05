use std::net::Ipv4Addr;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub header_length: usize,
    pub total_length: usize,
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub data_offset: usize,
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub opcode: u16, // 1 = Request, 2 = Reply
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Other(u8),
}

#[derive(Debug, Clone)]
pub enum PacketView {
    Ipv4 {
        eth: EthernetHeader,
        ip: Ipv4Header,
        transport: TransportHeader,
        payload: Vec<u8>,
    },
    Arp {
        eth: EthernetHeader,
        arp: ArpPacket,
    },
    Unknown,
}

pub struct PacketParser;

impl PacketParser {
    pub fn parse(raw: &[u8]) -> Option<PacketView> {
        if raw.len() < 14 {
            return None;
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&raw[0..6]);
        src_mac.copy_from_slice(&raw[6..12]);
        let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
        let eth = EthernetHeader { src_mac, dst_mac, ethertype };

        match ethertype {
            ETHERTYPE_IPV4 => {
                let ip_slice = &raw[14..];
                if ip_slice.len() < 20 { return None; }
                let ihl = (ip_slice[0] & 0x0F) as usize * 4;
                let total_len = u16::from_be_bytes([ip_slice[2], ip_slice[3]]) as usize;
                let proto = ip_slice[9];
                let src_ip = Ipv4Addr::new(ip_slice[12], ip_slice[13], ip_slice[14], ip_slice[15]);
                let dst_ip = Ipv4Addr::new(ip_slice[16], ip_slice[17], ip_slice[18], ip_slice[19]);

                let ip = Ipv4Header {
                    src_ip,
                    dst_ip,
                    protocol: proto,
                    header_length: ihl,
                    total_length: total_len,
                };

                let l4_slice = &ip_slice[ihl..];
                if proto == IP_PROTO_TCP && l4_slice.len() >= 20 {
                    let src_port = u16::from_be_bytes([l4_slice[0], l4_slice[1]]);
                    let dst_port = u16::from_be_bytes([l4_slice[2], l4_slice[3]]);
                    let data_offset = ((l4_slice[12] >> 4) as usize) * 4;
                    let flags = l4_slice[13];

                    let tcp = TcpHeader {
                        src_port,
                        dst_port,
                        syn: (flags & 0x02) != 0,
                        ack: (flags & 0x10) != 0,
                        fin: (flags & 0x01) != 0,
                        rst: (flags & 0x04) != 0,
                        data_offset,
                    };
                    let payload = if l4_slice.len() > data_offset {
                        l4_slice[data_offset..].to_vec()
                    } else {
                        Vec::new()
                    };
                    return Some(PacketView::Ipv4 { eth, ip, transport: TransportHeader::Tcp(tcp), payload });
                } else if proto == IP_PROTO_UDP && l4_slice.len() >= 8 {
                    let src_port = u16::from_be_bytes([l4_slice[0], l4_slice[1]]);
                    let dst_port = u16::from_be_bytes([l4_slice[2], l4_slice[3]]);
                    let len = u16::from_be_bytes([l4_slice[4], l4_slice[5]]) as usize;
                    let payload = if l4_slice.len() > 8 { l4_slice[8..].to_vec() } else { Vec::new() };
                    return Some(PacketView::Ipv4 { eth, ip, transport: TransportHeader::Udp(UdpHeader { src_port, dst_port, length: len }), payload });
                }

                Some(PacketView::Ipv4 { eth, ip, transport: TransportHeader::Other(proto), payload: Vec::new() })
            }
            ETHERTYPE_ARP => {
                let arp_slice = &raw[14..];
                if arp_slice.len() < 28 { return None; }
                let opcode = u16::from_be_bytes([arp_slice[6], arp_slice[7]]);
                let mut sender_mac = [0u8; 6];
                sender_mac.copy_from_slice(&arp_slice[8..14]);
                let sender_ip = Ipv4Addr::new(arp_slice[14], arp_slice[15], arp_slice[16], arp_slice[17]);
                let mut target_mac = [0u8; 6];
                target_mac.copy_from_slice(&arp_slice[18..24]);
                let target_ip = Ipv4Addr::new(arp_slice[24], arp_slice[25], arp_slice[26], arp_slice[27]);

                Some(PacketView::Arp {
                    eth,
                    arp: ArpPacket { opcode, sender_mac, sender_ip, target_mac, target_ip },
                })
            }
            _ => Some(PacketView::Unknown),
        }
    }
}
