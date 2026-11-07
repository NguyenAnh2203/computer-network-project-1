import argparse
import select
import socket
import sys
import time
from typing import Dict, Optional

from utils import PacketHeader, compute_checksum

MAX_CHUNK_BYTES = 1456
DEFAULT_TIMEOUT_SEC = 0.5


class RTPBaseSender:
    """Sliding Window Sender with Cumulative ACK (Go-Back-N mechanism)."""

    def __init__(self, dest_ip: str, dest_port: int, window_capacity: int):
        self.dest = (dest_ip, dest_port)
        self.window_size = window_capacity
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)

        self.segments: Dict[int, bytes] = {}
        self.total_segments = 0
        self.base_seq = 1
        self.next_seq = 1
        self.timer_epoch: Optional[float] = None

    @staticmethod
    def _create_frame(p_type: int, seq: int, body: bytes = b"") -> bytes:
        hdr = PacketHeader(type=p_type, seq_num=seq, length=len(body), checksum=0)
        hdr.checksum = compute_checksum(hdr / body)
        return bytes(hdr / body)

    @staticmethod
    def _parse_ack(raw_bytes: bytes) -> Optional[PacketHeader]:
        if len(raw_bytes) < 16:
            return None
        hdr = PacketHeader(raw_bytes[:16])
        payload = raw_bytes[16 : 16 + hdr.length]
        cksum = hdr.checksum
        hdr.checksum = 0
        if cksum != compute_checksum(hdr / payload):
            return None
        return hdr if hdr.type == 3 else None

    def _prepare_payloads(self, stream_data: bytes) -> None:
        slices = [
            stream_data[pos : pos + MAX_CHUNK_BYTES]
            for pos in range(0, len(stream_data), MAX_CHUNK_BYTES)
        ]
        self.total_segments = len(slices)
        for idx, chunk in enumerate(slices, start=1):
            self.segments[idx] = self._create_frame(p_type=2, seq=idx, body=chunk)

    def _execute_handshake(self) -> None:
        start_frame = self._create_frame(p_type=0, seq=0)
        self.sock.sendto(start_frame, self.dest)
        sent_timestamp = time.time()

        while True:
            readable, _, _ = select.select([self.sock], [], [], 0.05)
            if readable:
                try:
                    data, _ = self.sock.recvfrom(2048)
                    ack = self._parse_ack(data)
                    if ack and ack.seq_num == 1:
                        break
                except socket.error:
                    pass

            if time.time() - sent_timestamp >= DEFAULT_TIMEOUT_SEC:
                self.sock.sendto(start_frame, self.dest)
                sent_timestamp = time.time()

    def _transmit_sliding_window(self) -> None:
        while self.base_seq <= self.total_segments:
            # Emit pending packets within window capacity
            while (
                self.next_seq < self.base_seq + self.window_size
                and self.next_seq <= self.total_segments
            ):
                self.sock.sendto(self.segments[self.next_seq], self.dest)
                if self.timer_epoch is None:
                    self.timer_epoch = time.time()
                self.next_seq += 1

            # Check for incoming ACKs with short poll
            ready, _, _ = select.select([self.sock], [], [], 0.01)
            if ready:
                try:
                    raw_ack, _ = self.sock.recvfrom(2048)
                    ack_header = self._parse_ack(raw_ack)
                    if ack_header and ack_header.seq_num > self.base_seq:
                        self.base_seq = ack_header.seq_num
                        if self.base_seq < self.next_seq:
                            self.timer_epoch = time.time()
                        else:
                            self.timer_epoch = None
                except socket.error:
                    pass

            # Timeout check: retransmit entire unACKed window
            if self.timer_epoch and (time.time() - self.timer_epoch >= DEFAULT_TIMEOUT_SEC):
                for seq in range(self.base_seq, self.next_seq):
                    self.sock.sendto(self.segments[seq], self.dest)
                self.timer_epoch = time.time()

    def _finalize_connection(self) -> None:
        end_seq = self.total_segments + 1
        end_frame = self._create_frame(p_type=1, seq=end_seq)
        self.sock.sendto(end_frame, self.dest)

        finish_start = time.time()
        last_burst = time.time()

        while time.time() - finish_start < DEFAULT_TIMEOUT_SEC:
            ready, _, _ = select.select([self.sock], [], [], 0.02)
            if ready:
                try:
                    data, _ = self.sock.recvfrom(2048)
                    ack = self._parse_ack(data)
                    if ack and ack.seq_num >= end_seq:
                        break
                except socket.error:
                    pass

            if time.time() - last_burst >= 0.1:
                self.sock.sendto(end_frame, self.dest)
                last_burst = time.time()

    def run(self) -> None:
        raw_input = sys.stdin.buffer.read()
        self._prepare_payloads(raw_input)
        try:
            self._execute_handshake()
            self._transmit_sliding_window()
            self._finalize_connection()
        finally:
            self.sock.close()


def sender(receiver_ip, receiver_port, window_size):
    agent = RTPBaseSender(receiver_ip, receiver_port, window_size)
    agent.run()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="The IP address of the host that receiver is running on")
    parser.add_argument("receiver_port", type=int, help="The port number on which receiver is listening")
    parser.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
