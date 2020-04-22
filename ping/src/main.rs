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
use std::{env, process, thread, time};

// region packet const

// ICMP messages are encoded in an ICMP packet using IP[v4/v6] packets for transportation
const IPV4_HEADER_LEN: usize = 20;
// number of 32 bit words in the header -> 20/4 = 5
const IPV4_HEADER_WORD_LEN: u8 = 5;

const IPV6_HEADER_LEN: usize = 40;

// our ICMP packet defaults to 64 bytes
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PAYLOAD_LEN_DEFAULT: usize = 56;
// "word" position of the checksum field - starts at the second word (each are 2 bytes)
const ICMP_CHECKSUM_POS: usize = 2;
const ICMP_CODE: u8 = 0;

// endregion

const BUFF_SIZE: usize = 4096;
const DEFAULT_SLEEP_TIME: u64 = 1000;
const DEFAULT_TIMEOUT: u64 = 1;
const DEFAULT_TTL: u64 = 1;

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
        Some(input) => input.parse::<u64>().expect("the ttl must be an integer"),
        None => DEFAULT_TTL,
    };
    let icmp_payload_len = match arg_matches.value_of(main_clap::ARG_PACKET_SIZE) {
        Some(input) => input
            .parse::<usize>()
            .expect("the packet size must be an integer"),
        None => ICMP_PAYLOAD_LEN_DEFAULT,
    };
    let timeout = match arg_matches.value_of(main_clap::ARG_TIMEOUT) {
        Some(input) => input
            .parse::<u64>()
            .expect("the timeout must be an integer"),
        None => DEFAULT_TIMEOUT,
    };

    unsafe {
        register(SIGINT, || finish()).unwrap();
    }

    // let args: Vec<String> = env::args().collect();
    // let arg_ping_dest = &args[1];

    let address = resolve_ip_address(&arg_ping_dest).unwrap();
    let (ip_packet_size, protocol) = match address {
        IpAddr::V4(_) => {
            let size = IPV4_HEADER_LEN + ICMP_HEADER_LEN + icmp_payload_len;
            let protocol = Icmp;
            (size, protocol)
        }
        IpAddr::V6(_) => {
            let size = IPV6_HEADER_LEN + ICMP_HEADER_LEN + icmp_payload_len;
            let protocol = Icmpv6;
            (size, protocol)
        }
    };

    let duration = time::Duration::from_millis(DEFAULT_SLEEP_TIME);

    // we're using the network layer (3) to manipulate raw sockets and send icmp packets
    let channel_type = TransportChannelType::Layer3(protocol);
    let (mut sender, mut receiver) = match transport_channel(BUFF_SIZE, channel_type) {
        Ok((sender, receiver)) => (sender, receiver),
        Err(e) => panic!("Error initializing the channel {}", e),
    };

    // this iterator is used for received (incoming) icmp packets
    let mut receiver_iter = icmp_packet_iter(&mut receiver);

    println!(
        "PINGER: {}({}) with {} bytes of data",
        arg_ping_dest, address, ip_packet_size
    );

    loop {
        // easier to maintain lifetime of the buffers for packets by declaring them here
        // borrow them to create packets which are assigned the a same lifetime as these
        // buffers -> should go out of scope when buffers go out of scope
        let mut ip_packet_buf = vec![0u8; ip_packet_size];
        let mut icmp_packet_buf = vec![0u8; ICMP_HEADER_LEN + icmp_payload_len];
        // this has weird ergonomics that I'm not a huge fan of, but I'm still learning rust
        // I used a fn to create the packet, but had to create a new enum (SupportedPacketType) to
        // wrap the results because we can't return non-matching instance of classes that inherit
        // different traits
        let packet = create_packet(
            address,
            &mut ip_packet_buf,
            &mut icmp_packet_buf,
            icmp_payload_len,
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

        match receiver_iter.next_with_timeout(time::Duration::from_millis(DEFAULT_TIMEOUT)) {
            Ok(Some((_, ip_addr))) => {
                println!(
                    "{} bytes from {}: icmp_seq=1 ttl=55 time={} ms",
                    ip_packet_size,
                    ip_addr,
                    (time_sent.elapsed().as_micros() as f64) / 1000.0
                );
                unsafe { RECEIVED += 1 }
            }
            Ok(None) => {
                println!("packet timed out: time={} ms", DEFAULT_TIMEOUT);
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
    let reg_ipv6 = Regex::new("^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$")?;
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
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
    icmp_payload_size: usize,
) -> SupportedPacketType<'a> {
    return match address {
        IpAddr::V4(ip_addr) => SupportedPacketType::V4(create_ipv4_packet(
            ip_addr,
            ip_packet_buf,
            icmp_packet_buf,
            icmp_payload_size,
        )),
        IpAddr::V6(ip_addr) => SupportedPacketType::V6(create_ipv6_packet(
            ip_addr,
            ip_packet_buf,
            icmp_packet_buf,
            icmp_payload_size,
        )),
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
    icmp_payload_size: usize,
) -> MutableIpv4Packet<'a> {
    let mut ipv4_packet =
        MutableIpv4Packet::new(ip_packet_buf).expect("unable to create ipv4 packet");
    // I'm not entirely sure why we need to set the version to 4 since the MutableIpv4Packet should handle
    // it internally (IPv4 packets shold only be using IPv4).
    // not setting will cause the ping to fail (ie. server will not echo our pring)
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_WORD_LEN);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + icmp_payload_size) as u16);
    // TODO set ttl
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
    ip_packet_buf: &'a mut [u8],
    icmp_packet_buf: &'a mut [u8],
    icmp_payload_size: usize,
) -> MutableIpv6Packet<'a> {
    let mut ipv6_packet =
        MutableIpv6Packet::new(ip_packet_buf).expect("invalid packet buffer size");
    ipv6_packet.set_version(6);
    ipv6_packet.set_destination(dest);
    ipv6_packet.set_hop_limit(4);

    let mut icmp_packet = MutableIcmpv6Packet::new(icmp_packet_buf).unwrap();
    let checksum = checksum(&icmp_packet.packet_mut(), ICMP_CHECKSUM_POS);
    icmp_packet.set_checksum(checksum);
    icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    ipv6_packet.set_payload_length((ICMP_HEADER_LEN + icmp_payload_size) as u16);
    ipv6_packet.set_payload(icmp_packet.packet_mut());

    unimplemented!("IPV6 is currently unimplemented");
}

unsafe fn finish() {
    // TODO print all info out
    println!("---  ping statistics ---");

    let packet_loss = (SENT - RECEIVED) / (SENT + RECEIVED) * 100;

    println!(
        "\n{} packets transmitted, {} received, {}% packet loss",
        SENT, RECEIVED, packet_loss,
    );

    process::exit(0);
}
