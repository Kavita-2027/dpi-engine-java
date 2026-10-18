# DPI Engine (Java)

A Deep Packet Inspection engine in plain Java 21 that reads PCAP captures,
tracks network flows, identifies the website or app from TLS SNI / HTTP Host,
applies blocking rules, and writes the allowed traffic to a new PCAP file.



## Features
- PCAP reader (both byte orders, micro/nanosecond timestamps) and writer
- Ethernet / IPv4 / TCP / UDP parsing with bounds checking
- Bidirectional flow tracking (a request and its reply share one flow)
- Hostname extraction: TLS Client Hello SNI and HTTP Host header
- Classification by domain suffix (e.g. `www.youtube.com` -> YouTube)
- Blocking rules by client IP, app, or domain; whole flows are blocked
- Statistics report; malformed packets are counted and dropped

## Build and run
Requires JDK 21 and Maven.

    mvn test
    mvn package
    java -cp target/classes com.kavita.dpi.cli.Main capture.pcap --block-app YouTube --block-domain facebook.com --output filtered.pcap

## Design
pcap -> parser -> flow table -> extract -> classify/rules -> writer

## Testing
14 unit tests (`mvn test`) covering the PCAP reader/writer, flow keys,
SNI/Host extraction, classification and rules.

Verified in Wireshark: the sample capture has 77 packets; with
`--block-app YouTube --block-domain facebook.com` the output has 75. The
YouTube Client Hello is present in the input and absent from the output.

## Limitations
- IPv4 over Ethernet only (no IPv6, VLAN, or fragment reassembly)
- A TLS Client Hello split across several TCP segments is not detected
- QUIC/HTTP3 and encrypted SNI (ECH) are not handled
- Packets sent before the Client Hello are forwarded, since the app is not yet known
- Single-threaded