extern crate clap;

use clap::{App, Arg, ArgMatches};

pub const ARG_ADDRESS : &'static str = "ping-address";
pub const ARG_TTL : &'static str = "ttl";
pub const ARG_PACKET_SIZE : &'static str = "packet-size";
pub const ARG_TIMEOUT : &'static str= "timeout";

pub fn clap_desc() -> ArgMatches<'static> {
    return App::new("Ping")
        .version("0.1.0")
        .author("Richard Wei <therichardwei@gmail.com>")
        .arg(
            Arg::with_name(ARG_ADDRESS)
                .index(1)
                .takes_value(true)
                .help("The address or hostname to ping"),
        )
        .arg(
            Arg::with_name(ARG_TTL)
                .short("t")
                .takes_value(true)
                .help("How long the packet is allowed to be passed along before it 'dies' (1 - 255, default = 64)"),
        )
        .arg(
            Arg::with_name(ARG_PACKET_SIZE)
                .short("s")
                .takes_value(true)
            
                .help("Number of bytes to be sent in the ICMP packet (default is 8 for header + 56 for body). (8 - 1024, default = 64)"),
        )
        .arg(
            Arg::with_name(ARG_TIMEOUT)
                .short("W")
                .takes_value(true)
                .help("Seconds to wait to receive a sent response (1 - 20, default = 1)"),
        )
        .get_matches();
}
