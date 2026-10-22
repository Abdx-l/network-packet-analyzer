# Network Packet Analyzer

Read classic pcap files without a packet parsing dependency. The analyzer decodes Ethernet, IPv4, TCP, and UDP headers, groups IP traffic by five tuple, counts bytes and protocols, and identifies TCP sequence numbers repeated within a flow.

```sh
python packet_analyzer.py sample.pcap --top 10 --json summary.json
python -m unittest discover -s tests -v
```

Input is an existing capture file. The parser supports little and big endian pcap headers with microsecond or nanosecond timestamps and Ethernet link type 1. Truncated and unsupported packets are counted separately. Retransmission detection is a sequence-number heuristic, so inspect a capture in Wireshark for deeper TCP diagnosis.

