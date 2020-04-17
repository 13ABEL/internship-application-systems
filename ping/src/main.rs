extern crate pnet;

use pnet::datalink::{Channel, MacAddr, NetworkInterface};


use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::transport::{TransportChannelType,transport_channel, icmp_packet_iter};
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp::{IcmpPacket};

use std::net::{AddrParseError, IpAddr, Ipv4Addr};

const BUFF_SIZE : usize = 4096;

fn main() -> std::io::Result<()> {
    
    let address = Ipv4Addr::new(8,8,8,8);
    let channel_type = TransportChannelType::Layer3(Icmp);
    
    let (mut sender, mut receiver) = match transport_channel(BUFF_SIZE, channel_type){
        Ok((sender, receiver)) => (sender, receiver),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    match sender.send_to(ethernet_packet, IpAddr::V4(address)){
        Ok(result) => println!("packet sent with {} bytes ", result),
        Err(e) => panic!("Error sending packet {}", e),
    }; 

    let mut receiver_iter = icmp_packet_iter(&mut receiver);
    match receiver_iter.next() {
        Ok((packet, ip_addr)) => println!("packet response received {} {} ", packet.get_checksum(), ip_addr),
        Err(e) => panic!("Error receiving packet {}", e),
    }

    
    // sender.send_to(packet: T, destination: IpAddr)
    // datalink::channel(network_interface: &NetworkInterface, configuration: Config);



    return Ok(());
}
