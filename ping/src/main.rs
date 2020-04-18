extern crate pnet;

use pnet::packet::icmp::{echo_request, IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType};
use pnet::util::checksum;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{thread, time};

const BUFF_SIZE: usize = 4096;
const DEFAULT_SLEEP_TIME: u64 = 1000;

/*
OSI model
ICMP messages are encoded in an ICMP packet
ICMP use IP[v4/v6] for transportation
*/
const IPV4_HEADER_LEN: usize = 21;

// our ICMP packet is 40 bytes
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PAYLOAD_LEN: usize = 32;
// "word" position of the checksum field - starts at the second word (each are 2 bytes)
const ICMP_CHECKSUM_POS: usize = 2;

const ICMP_CODE: u8 = 0;

enum SupportedPacketType<'a> {
    V4(MutableIpv4Packet<'a>),
    V6(MutableIpv6Packet<'a>),
}

fn main() {
    // TODO add v6 routes
    let address = Ipv4Addr::new(192, 168, 0, 1);
    let duration = time::Duration::from_millis(DEFAULT_SLEEP_TIME);

    // we're using the network layer (3) to manipulate raw sockets
    let channel_type = TransportChannelType::Layer3(Icmp);
    let (mut sender, mut receiver) = match transport_channel(BUFF_SIZE, channel_type) {
        Ok((sender, receiver)) => (sender, receiver),
        Err(e) => panic!("Error initializing the channel {}", e),
    };

    let mut receiver_iter = icmp_packet_iter(&mut receiver);

    loop {
        // easier to maintain lifetime of the buffers for packets by declaring them here
        // borrow them to create packets which are assigned the a same lifetime as these
        // buffers -> should go out of scope when buffers go out of scope
        let mut ipv4_packet_buf = [0; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN];
        let mut icmp_packet_buf = [0; ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN];
        // this has weird ergonomics that I'm not a huge fan of, but I'm still learning rust
        // I used a fn to create the packet, but had to create a bew enum (SupportedPacketType) to
        // wrap the results because we can't return non-matching instance of classes that inherit
        // different traits
        let packet = create_packet(
            IpAddr::V4(address),
            &mut ipv4_packet_buf,
            &mut icmp_packet_buf,
        );
        let send_result = match packet {
            SupportedPacketType::V4(packet) => sender.send_to(packet, IpAddr::V4(address)),
            SupportedPacketType::V6(packet) => sender.send_to(packet, IpAddr::V4(address)), // TODO change to V6 once we implement
        };
        match send_result {
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
    }
}

/*
creates a packet for a given address based on address spec
ie. Ipv4Packet for Ipv4Addr and Ipv6Packet for Ipv6Addr
*/
fn create_packet<'a>(
    address: IpAddr,
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
) -> SupportedPacketType<'a> {
    return match address {
        IpAddr::V4(ip_addr) => {
            SupportedPacketType::V4(create_ipv4_packet(ip_addr, ip_packet_buf, icmp_packet_buf))
        }
        IpAddr::V6(ip_addr) => {
            SupportedPacketType::V6(create_ipv6_packet(ip_addr, ip_packet_buf, icmp_packet_buf))
        }
    };
}

/*
I referenced this: https://codereview.stackexchange.com/questions/208875/traceroute-implementation-in-rust
which helped me understand I had to wrap my ICMP packet within a IP[v4/v6] packet
*/
fn create_ipv4_packet<'a>(
    dest: Ipv4Addr,
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
) -> MutableIpv4Packet<'a> {
    let mut ipv4_packet = MutableIpv4Packet::new(ip_packet_buf).unwrap();
    // I'm not entirely sure why we need to set the version to 4 since the MutableIpv4Packet should handle
    // it internally (IPv4 packets shold only be using IPv4).
    // not setting will cause the ping to fail (ie. server will not echo our pring)
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    // TODO set ttl
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet = MutableIcmpPacket::new(icmp_packet_buf).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = checksum(&icmp_packet.packet_mut(), ICMP_CHECKSUM_POS);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());

    return ipv4_packet;
}

fn create_ipv6_packet<'a>(
    dest: Ipv6Addr,
    buffer_ip: &'a mut [u8],
    buffer_icmp: &'a mut [u8],
) -> MutableIpv6Packet<'a> {
    let mut ipv6_packet = MutableIpv6Packet::new(buffer_ip).unwrap();
    // TODO
    return ipv6_packet;
}
