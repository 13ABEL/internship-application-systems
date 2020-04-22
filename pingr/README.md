# PINGR - a rust ping clone
This is a (basic) commandline ping cline written in Rust

## Build instructions
From the project root:
```bash
# the executable can be found in [./target/debug/ping]
cargo build
```

## Usage
Run the executable with either the hostname or IP destination address you want to ping.
PINGER will send icmp echo requests to the destination in a loop and display response info until you terminate the program. 

Termination with SIGINT (ctrl + c) will display the total number of packets transmitted and lost, as well as packet loss

```bash
sudo ./target/debug/ping 127.0.0.1
```
Note: this need to run this as su because we need to use raw sockets to send icmp packets over ipv4/ipv6


## Features:
- setting custom **ttl**: the number of times a packet can be passed along before it is discarded - between 0 and 255 (default = 64)
- set custom **icmp packet size**(including header): between 8 and 1024 (default = 64). The size constraint is explained in the see more section
- set custom **time out**: time to wait for a response - between 1 and 20 seconds (default = 1) 

for more information, you can run the compiled executable with the help flag
```bash
./target/debug/ping 127.0.0.1 --help
```

What doesn't work:
- sending large packets using IPV4: the max packet size should be 65535, but it yields an error when I try to send it so I've set a hard limit for now
```
Error sending packet Message too long (os error 90)
```
- IPV6: The ipv6 logic has been implemented, but I got blocked an error. I spent a while trying to debug this but haven't been able to find a solution (ipv6 is enabled on my device).
```
Error sending packet Address family not supported by protocol (os error 97)
```