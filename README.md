# Packet Sniffer

Packet sniffer program. Scans interface in promiscuous mode and displays info about arrived packets.

Supported protocols are ETHERNET, ARP, IPv4, IPv6, TCP, UDP.

## Project files

Project consists of following files and directories:

* ./main.cpp
* ./Makefile
* ./README.md
* ./manual.pdf
* ./src/
* ./src/utils.h
* ./src/utils.cpp
* ./src/sniffer.h
* ./src/sniffer.cpp
* ./src/frame_parser.h
* ./src/frame_parser.cpp

## Prerequisites

Program is made for UNIX operating system. C++17 (or later) is used for the implementation. Make program is required if you will to use makefile.


## Installation

To compile the program, run this command in the console in the root directory:

```constole
make
```

## Program parameters

| Parameter         | Argument    | Description                |
|-------------------|-------------|----------------------------|
| -h \| --help      | none        | print help and exit        |
| -i \| --interface | [INTERFACE] | interface to sniff on      |
| -p                | [PORT]      | sniff this port            |
| -t \| --tcp       | none        | sniff TCP                  |
| -u \| --udp       | none        | sniff UDP                  |
| --icmp            | none        | sniff ICMP                 |
| --arp             | none        | sniff ARP                  |
| -n                | [NUM]       | number of packets to print |

All parameters are optional.

If interface parameter is entered with no interface specified, or no interface parameter is entered at all, program prints all available interfaces on device.

If no protocol parameter is entered, all protocols are sniffed. If no port parameter is entered, all ports are sniffed. If no -n parameter is entered, sniffs one packet.

If port parameter is entered, but neither TCP nor UDP are entered, both of these are assumemed automatically.

With -n parameter equal to 0, program sniffs packets until program is ended manually.

## Usage

**Print all available interfaces**

```console
./ipk-sniffer --interface
```

**Sniff one packet on wlo1 interface**

```console
./ipk-sniffer -i wlo1
```

**Sniff ten TCP packets on wlo1 interface with port 80**

```console
./ipk-sniffer -i wlo1 --tcp -p 80 -n 10
```

**Sniff all ARP and ICMP packets on interface wlo1**

```console
./ipk-sniffer -i wlo1 --arp --icmp -n 0
```

**Sniff all ARP packets; and all TCP and UDP packets with port 100 on interface wlo1**

```console
./ipk-sniffer -i wlo1 --arp --port 100 -n 0
```

**Sniff all ARP and ICMP packets; and all TCP and UDP packets with port 120 on interface wlo1**

```console
./ipk-sniffer -i wlo1 -p 120
```

**End program manually**

Press ctrl+C.

## Author

Program made by Patrik Korytár. 2022
