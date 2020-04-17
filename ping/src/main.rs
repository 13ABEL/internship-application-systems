extern crate pnet;

use pnet::packet::icmp::{echo_request, IcmpCode, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::packet::MutablePacket;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType};
use pnet::util::checksum;

use std::net::{IpAddr, Ipv4Addr};
use std::{thread, time};

const BUFF_SIZE: usize = 4096;
const DEFAULT_SLEEP_TIME: u64 = 1000;

// icmp doesn't use codes
const ICMP_CODE: u8 = 0;

fn main() {
    // let address = Ipv4Addr::new(8,8,8,8);
    let address = Ipv4Addr::new(192, 168, 0, 1);
    let duration = time::Duration::from_millis(DEFAULT_SLEEP_TIME);

    let channel_type = TransportChannelType::Layer3(Icmp);
    let (mut sender, mut receiver) = match transport_channel(BUFF_SIZE, channel_type) {
        Ok((sender, receiver)) => (sender, receiver),
        Err(e) => panic!("Error initializing the channel {}", e),
    };

    let mut receiver_iter = icmp_packet_iter(&mut receiver);

    // create packet to send (note 68 is max size)
    let mut packet_buffer = [0u8; 64];

    // loop {
    let mut out_packet = MutableIcmpPacket::new(&mut packet_buffer).unwrap();
    // let mut out_packet = echo_request::EchoRequestPacket::new(&mut packet_buffer).unwrap();

    out_packet.set_icmp_type(IcmpTypes::EchoRequest);
    out_packet.set_icmp_code(IcmpCode(ICMP_CODE));

    let checksum = checksum(out_packet.packet_mut(), 2);
    out_packet.set_checksum(checksum);

    match sender.send_to(out_packet, IpAddr::V4(address)) {
        Ok(result) => println!("packet sent with {} bytes ", result),
        Err(e) => panic!("Error sending packet {}", e),
    };

    match receiver_iter.next_with_timeout(time::Duration::from_millis(2 * DEFAULT_SLEEP_TIME)) {
        Ok(Some((packet, ip_addr))) => println!(
            "packet response received {} {} ",
            packet.get_checksum(),
            ip_addr
        ),
        Ok(None) => println!("timeout, no response"),
        Err(e) => println!("Error receiving packet {}", e),
    }

    thread::sleep(duration);
    // }
}
