# PINGER - a Rust ping clone
This is a (basic) commandline ping cline written in Rust

## Build instructions
From the project root
```bash
# the executable can be found in [./target/debug/ping]
cargo build
```

## Usage
Run the executable with either the hostname or IP destination address you want to ping.
PINGER will send icmp echo requests to the destination in a loop and display response info until you terminate the program. 

Terminatign with SIGINT (ctrl + c) will display the total number of packets transmitted and lost, as well as packet loss

```bash
sudo ./target/debug/ping 127.0.0.1
```
Note: this need to run this as su because we need to use raw sockets to send icmp packets over ipv4/ipv6


## Features:
- setting custom **ttl**: the number of times a packet can be passed along before it is discarded (default = 64)
- set custom **icmp packet size**(including header): between 8 and 65535 (default = 64)
- set custom **time out**: time to wait for a response - between 1 and 20 seconds (default = 1) 

for more information, you can run the compiled executable with the help flag
```
./target/debug/ping 127.0.0.1 --help
```

What doesn't work:
- IPV6: The ipv6 logic has been implemented, but I got blocked an error. I spent a while trying to debug this but haven't been able to find a solution (ipv6 is enabled on my device).
```
Error sending packet Address family not supported by protocol (os error 97)
```