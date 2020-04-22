extern crate clap;

use clap::{App, Arg, ArgMatches};

pub const ARG_ADDRESS : &'static str = "ping-address";
pub const ARG_TTL : &'static str = "ttl";
pub const ARG_PACKET_SIZE : &'static str = "packet-size";
pub const ARG_TIMEOUT : &'static str= "timeout";


pub fn clap_desc() -> ArgMatches<'static> {
    return App::new("My Test Program")
        .version("0.1.0")
        .author("Hackerman Jones <hckrmnjones@hack.gov>")
        .about("Teaches argument parsing")
        .arg(
            Arg::with_name(ARG_ADDRESS)
                .index(1)
                .takes_value(true)
                .help("The address to ping"),
        )
        .arg(
            Arg::with_name(ARG_TTL)
                .short("t")
                .takes_value(true)
                .help("How long the packet is alloweod to be passed along before it 'dies'"),
        )
        .arg(
            Arg::with_name(ARG_PACKET_SIZE)
                .short("s")
                .takes_value(true)
            
                .help("Number of bytes to be sent in the ICMP packet (default is 8 for header + 56 for body)"),
        )
        .arg(
            Arg::with_name(ARG_TIMEOUT)
                .short("W")
                .takes_value(true)
                .help("Seconds to wait to receive a sent response"),
        )
        .get_matches();
}
