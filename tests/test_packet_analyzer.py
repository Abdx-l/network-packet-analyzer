import socket
import struct
import tempfile
from pathlib import Path
import unittest

from packet_analyzer import analyze, decode, packets


def tcp_frame(seq=42):
    tcp = struct.pack("!HHIIHHHH", 1234, 80, seq, 0, 5 << 12, 0, 0, 0) + b"abc"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


class PacketTests(unittest.TestCase):
    def test_flows_and_repeated_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            frames = [tcp_frame(), tcp_frame(), tcp_frame(45), b"\x00"]
            with path.open("wb") as stream:
                stream.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
                for frame in frames:
                    stream.write(struct.pack("<IIII", 1, 100, len(frame), len(frame)) + frame)
            self.assertEqual(len(list(packets(path))), 4)
            report = analyze(path)
            self.assertEqual(report["protocols"], {"TCP": 3})
            self.assertEqual(report["top_flows"][0]["retransmissions"], 1)
            self.assertEqual(report["skipped"], {"truncated": 1})

    def test_rejects_invalid_lengths(self):
        frame = bytearray(tcp_frame())
        frame[16:18] = b"\x00\x10"
        _, reason = decode(bytes(frame))
        self.assertEqual(reason, "truncated")


if __name__ == "__main__":
    unittest.main()

