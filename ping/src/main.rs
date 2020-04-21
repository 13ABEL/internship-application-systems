extern crate pnet;
extern crate regex;

use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType};
use pnet::util::checksum;

use regex::Regex;
use signal_hook::{register, SIGINT};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Instant;
use std::{env, process, thread, time};
use dns_lookup::{lookup_host};

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

static mut sent: usize = 0;
static mut received: usize = 0;
// static time: Instant = Instant::zero();

fn main() {
    unsafe {
        register(SIGINT, || finish()).unwrap();
    }

    let args: Vec<String> = env::args().collect();
    let arg_ping_dest = &args[1];
    let address = resolve_ip_address(arg_ping_dest);
    let duration = time::Duration::from_millis(DEFAULT_SLEEP_TIME);

    // we're using the network layer (3) to manipulate raw sockets
    let channel_type = TransportChannelType::Layer3(Icmp);
    let (mut sender, mut receiver) = match transport_channel(BUFF_SIZE, channel_type) {
        Ok((sender, receiver)) => (sender, receiver),
        Err(e) => panic!("Error initializing the channel {}", e),
    };

    let mut receiver_iter = icmp_packet_iter(&mut receiver);

    let packet_size = IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN;
    println!(
        "PINGER: {}({}) sent with {} bytes",
        arg_ping_dest, address, packet_size
    );

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
        let packet = create_packet(address, &mut ipv4_packet_buf, &mut icmp_packet_buf);
        let time_sent = Instant::now();
        let send_result = match packet {
            SupportedPacketType::V4(packet) => sender.send_to(packet, address),
            SupportedPacketType::V6(packet) => sender.send_to(packet, address),
        };
        match send_result {
            Ok(_) => {
                // println!("packet sent with {} bytes", result);
                unsafe { sent += 1 }
            }
            Err(e) => panic!("Error sending packet {}", e),
        };
        match receiver_iter.next_with_timeout(time::Duration::from_millis(DEFAULT_SLEEP_TIME)) {
            Ok(Some((_, ip_addr))) => {
                //
                println!(
                    "{} bytes from {}: icmp_seq=1 ttl=55 time={} ms",
                    0,
                    ip_addr,
                    (time_sent.elapsed().as_micros() as f64) / 1000.0
                );
                unsafe { received += 1 }
            }
            Ok(None) => println!("timeout, no response"),
            Err(e) => println!("Error receiving packet {}", e),
        }
        thread::sleep(duration);
    }
}

/*
parse input as IP address
*/
fn resolve_ip_address(input: &String) -> IpAddr {
    // regex taken from:
    // ipv4: https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
    // ipv6: https://www.oreilly.com/library/view/regular-expressions-cookbook/9781449327453/ch08s17.html
    // domain: https://regexr.com/3au3g
    let reg_ipv4 = Regex::new(r#"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"#).unwrap();
    let reg_ipv6 = Regex::new("^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$").unwrap();
    let reg_hostname =
        Regex::new(r#"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){0,2}[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"#)
            .unwrap();

    let ip_addr: IpAddr;
    // determine whether IP address or domain is supplied
    if reg_hostname.is_match(input) {
        let lookup_results = lookup_host(input).unwrap();
        // for address in lookup_results {
        //     println!("resolved address {} ipv4 {} ipv6 {}", address, address.is_ipv4(), address.is_ipv6(),);
        // }
        // TODO allow force v4/v6, but for now just use v6 (ie. the first result)
        match lookup_results.len() {
            // default to ipv4 if both are available since ipv6 is currently not working
            2 => ip_addr = lookup_results[1],
            1 => ip_addr = lookup_results[0],
            _ => panic!("host name lookup returned with not results"),
        }
    } else if reg_ipv4.is_match(input) || reg_ipv6.is_match(input) {
        ip_addr = input.parse().unwrap();
    } else {
        panic!("Please enter a valid domain or IP address");
    }

    return ip_addr;
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
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
) -> MutableIpv6Packet<'a> {
    let mut ipv6_packet = MutableIpv6Packet::new(ip_packet_buf).unwrap();
    ipv6_packet.set_version(6);
    // ipv6_packet.set_icmp_type()

    return ipv6_packet;
}

unsafe fn finish() {
    // TODO print all info out
    println!("--- 2607:f8b0:400b:808::200e ping statistics ---");

    let packet_loss = (sent - received) / (sent + received) * 100;

    println!(
        "\n{} packets transmitted, {} received, {}% packet loss, time {} ms",
        sent, received, packet_loss, 0
    );

    process::exit(0);
}
