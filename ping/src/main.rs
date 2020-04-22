mod main_clap;

extern crate pnet;
extern crate regex;

use pnet::packet::icmp::{IcmpCode, IcmpTypes, MutableIcmpPacket};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};

use pnet::packet::ip::IpNextHeaderProtocols::{Icmp, Icmpv6};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType};
use pnet::util::checksum;

use dns_lookup::lookup_host;
use regex::Regex;
use signal_hook::{register, SIGINT};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use std::{process, thread, time};

// region packet const

// ICMP messages are encoded in an ICMP packet using IP[v4/v6] packets for transportation
const IPV4_HEADER_LEN: usize = 20;
// number of 32 bit words in the header -> 20/4 = 5
const IPV4_HEADER_WORD_LEN: u8 = 5;

const IPV6_HEADER_LEN: usize = 40;

// our ICMP packet defaults to 64 bytes
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PAYLOAD_LEN_DEFAULT: u16 = 56;
// "word" position of the checksum field - starts at the second word (each are 2 bytes)
const ICMP_CHECKSUM_POS: usize = 1;
const ICMP_CODE: u8 = 0;

// endregion

const DEFAULT_BUFF_SIZE: usize = 4096;
const DEFAULT_SLEEP_TIME: u64 = 1000;
const DEFAULT_TIMEOUT: usize = 1;
const DEFAULT_TTL: u8 = 64;
// the max ipv4 packet size should be 65535, but results in a error when sending 
const MAX_IPV4_PACKET_LEN: usize = 1044;
const MAX_ICMP_PACKET_LEN: usize = MAX_IPV4_PACKET_LEN - IPV4_HEADER_LEN;
const MAX_TTL: u64 = 255;
const MAX_TIMEOUT: usize = 20;

enum SupportedPacketType<'a> {
    V4(MutableIpv4Packet<'a>),
    V6(MutableIpv6Packet<'a>),
}

static mut SENT: usize = 0;
static mut RECEIVED: usize = 0;

fn main() {
    // set up values based on args
    let arg_matches = main_clap::clap_desc();
    let arg_ping_dest = match arg_matches.value_of(main_clap::ARG_ADDRESS) {
        Some(input) => String::from(input),
        None => panic!("Please supply the address to ping"),
    };
    let ttl = match arg_matches.value_of(main_clap::ARG_TTL) {
        Some(input) => {
            let full_ttl = input.parse::<u64>().expect("the ttl must be an integer");
            match full_ttl {
                1..=MAX_TTL => full_ttl as u8,
                _ => panic!("the ttl is 1 to {}", MAX_TTL),
            }
        }
        None => DEFAULT_TTL,
    };

    let icmp_packet_len: usize = match arg_matches.value_of(main_clap::ARG_PACKET_SIZE) {
        Some(input) => {
            let full_payload_len = input
                .parse::<usize>()
                .expect("the packet size must be an integer");

            match full_payload_len {
                8..=MAX_ICMP_PACKET_LEN => full_payload_len,
                _ => panic!(
                    "the icmp packet length must be between {} and {} bytes",
                    ICMP_HEADER_LEN, MAX_ICMP_PACKET_LEN
                ),
            }
        }
        None => ICMP_PAYLOAD_LEN_DEFAULT as usize,
    };
    let timeout_length = match arg_matches.value_of(main_clap::ARG_TIMEOUT) {
        Some(input) => {
            let full_timeout_len = input
                .parse::<usize>()
                .expect("the timeout must be an integer");

            match full_timeout_len {
                1..=MAX_TIMEOUT => full_timeout_len,
                _ => panic!(
                    "the timeout must be between {} and {} seconds",
                    1, MAX_TIMEOUT
                ),
            }
        }
        None => DEFAULT_TIMEOUT,
    };

    // register the SIGINT handler
    unsafe {
        register(SIGINT, || finish()).unwrap();
    }

    let address = resolve_ip_address(&arg_ping_dest).unwrap();
    let (ip_packet_size, protocol) = match address {
        IpAddr::V4(_) => {
            let size = IPV4_HEADER_LEN + icmp_packet_len;
            let protocol = Icmp;
            (size, protocol)
        }
        IpAddr::V6(_) => {
            let size = IPV6_HEADER_LEN + icmp_packet_len;
            let protocol = Icmpv6;
            (size, protocol)
        }
    };

    let duration = time::Duration::from_millis(DEFAULT_SLEEP_TIME);

    // we're using the network layer (3) to manipulate raw sockets and send icmp packets
    let channel_type = TransportChannelType::Layer3(protocol);
    let (mut sender, mut receiver) = match transport_channel(DEFAULT_BUFF_SIZE, channel_type) {
        Ok((sender, receiver)) => (sender, receiver),
        Err(e) => panic!("Error initializing the channel {}", e),
    };

    // this iterator is used for received (incoming) icmp packets
    let mut receiver_iter = icmp_packet_iter(&mut receiver);

    println!(
        "PINGER: {}({}) with {} bytes of data",
        arg_ping_dest,
        address,
        icmp_packet_len
    );

    loop {
        // easier to maintain lifetime of the buffers for packets by declaring them here
        // borrow them to create packets which are assigned the a same lifetime as these
        // buffers -> should go out of scope when buffers go out of scope
        let mut ip_packet_buf = vec![0u8; ip_packet_size];
        let mut icmp_packet_buf = vec![0u8; icmp_packet_len];
        // this has weird ergonomics that I'm not a huge fan of, but I'm still learning rust
        // I used a fn to create the packet, but had to create a new enum (SupportedPacketType) to
        // wrap the results because we can't return non-matching instance of classes that inherit
        // different traits
        let packet = create_packet(
            address,
            ttl,
            &mut ip_packet_buf,
            &mut icmp_packet_buf,
            icmp_packet_len,
        );
        let time_sent = Instant::now();
        let send_result = match packet {
            SupportedPacketType::V4(packet) => sender.send_to(packet, address),
            SupportedPacketType::V6(packet) => sender.send_to(packet, address),
        };
        match send_result {
            Ok(_) => {
                // println!("packet sent with {} bytes", result);
                unsafe { SENT += 1 }
            }
            Err(e) => panic!("Error sending packet {}", e),
        };

        match receiver_iter.next_with_timeout(time::Duration::from_secs(timeout_length as u64)) {
            Ok(Some((_, ip_addr))) => {
                println!(
                    "{} bytes from {}: ttl={} time={} ms",
                    icmp_packet_len,
                    ip_addr,
                    ttl,
                    (time_sent.elapsed().as_micros() as f64) / 1000.0
                );
                unsafe { RECEIVED += 1 }
            }
            Ok(None) => {
                println!(
                    "packet timed out: time={} ms",
                    time_sent.elapsed().as_millis()
                );
            }
            Err(e) => println!("Error receiving packet {}", e),
        }
        thread::sleep(duration);
    }
}

/*
parse input as IP address
*/
fn resolve_ip_address(input: &String) -> Result<IpAddr, Box<dyn Error>> {
    // regex taken from:
    // ipv4: https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
    // ipv6: https://www.oreilly.com/library/view/regular-expressions-cookbook/9781449327453/ch08s17.html
    // domain: https://regexr.com/3au3g
    let reg_ipv4 = Regex::new(r#"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"#)?;
    let reg_ipv6 = Regex::new("^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$")?;
    let reg_hostname = Regex::new(
        r#"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){0,2}[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"#,
    )?;

    let ip_addr: IpAddr;
    // determine whether IP address or domain is supplied
    if reg_hostname.is_match(input) {
        let lookup_results = lookup_host(input)?;
        // TODO allow force v4/v6, but make v6 the default selection if it is available
        // default to ipv4 if both are "available" since ipv6 is currently not working
        match lookup_results.len() {
            2 => ip_addr = lookup_results[1],
            1 => ip_addr = lookup_results[0],
            _ => panic!("host name lookup returned with not results"),
        }
    } else if reg_ipv4.is_match(input) || reg_ipv6.is_match(input) {
        ip_addr = input.parse()?;
    } else {
        panic!("Please enter a valid domain or IP address");
    }

    return Ok(ip_addr);
}

/*
creates a packet for a given address based on address spec
ie. Ipv4Packet for Ipv4Addr and Ipv6Packet for Ipv6Addr
*/
fn create_packet<'a>(
    address: IpAddr,
    ttl: u8,
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
    icmp_packet_len: usize,
) -> SupportedPacketType<'a> {
    return match address {
        IpAddr::V4(ip_addr) => SupportedPacketType::V4(create_ipv4_packet(
            ip_addr,
            ttl,
            ip_packet_buf,
            icmp_packet_buf,
            icmp_packet_len,
        )),
        IpAddr::V6(ip_addr) => SupportedPacketType::V6(create_ipv6_packet(
            ip_addr,
            ttl,
            ip_packet_buf,
            icmp_packet_buf,
            icmp_packet_len,
        )),
    };
}

/*
I referenced this: https://codereview.stackexchange.com/questions/208875/traceroute-implementation-in-rust
which helped me understand I had to wrap my ICMP packet within a IP[v4/v6] packet
*/
fn create_ipv4_packet<'a>(
    dest: Ipv4Addr,
    ttl: u8,
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
    icmp_packet_len: usize,
) -> MutableIpv4Packet<'a> {
    let mut ipv4_packet =
        MutableIpv4Packet::new(ip_packet_buf).expect("unable to create ipv4 packet");
    // I'm not entirely sure why we need to set the version to 4 since the MutableIpv4Packet should handle
    // it internally (IPv4 packets shold only be using IPv4).
    // not setting will cause the ping to fail (ie. server will not echo our pring)
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_WORD_LEN);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + icmp_packet_len) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet =
        MutableIcmpPacket::new(icmp_packet_buf).expect("unable to create icmp packet");
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCode::new(ICMP_CODE));

    let checksum = checksum(&icmp_packet.packet_mut(), ICMP_CHECKSUM_POS);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());

    return ipv4_packet;
}

fn create_ipv6_packet<'a>(
    dest: Ipv6Addr,
    ttl: u8,
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
    icmp_packet_len: usize,
) -> MutableIpv6Packet<'a> {
    let mut ipv6_packet =
        MutableIpv6Packet::new(ip_packet_buf).expect("invalid packet buffer size");
    ipv6_packet.set_version(6);
    ipv6_packet.set_destination(dest);
    ipv6_packet.set_hop_limit(ttl);

    let mut icmp_packet = MutableIcmpv6Packet::new(icmp_packet_buf).unwrap();
    let checksum = checksum(&icmp_packet.packet_mut(), ICMP_CHECKSUM_POS);
    icmp_packet.set_checksum(checksum);
    icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    ipv6_packet.set_payload_length((ICMP_HEADER_LEN + icmp_packet_len) as u16);
    ipv6_packet.set_payload(icmp_packet.packet_mut());

    return ipv6_packet;
    // unimplemented!("IPV6 is currently unimplemented");
}

unsafe fn finish() {
    println!("\n--- ping statistics ---");

    let packet_loss = (SENT - RECEIVED) / (SENT + RECEIVED) * 100;
    println!(
        "{} packets transmitted, {} received, {}% packet loss",
        SENT, RECEIVED, packet_loss,
    );

    process::exit(0);
}
