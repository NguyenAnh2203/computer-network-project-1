import argparse
import socket
import sys
from typing import Dict, Optional, Tuple

from utils import PacketHeader, compute_checksum


class RTPBaseReceiver:
    """Sliding Window Receiver with Cumulative ACK and out-of-order buffering."""

    def __init__(self, bind_ip: str, bind_port: int, window_capacity: int):
        self.bind_address = (bind_ip, bind_port)
        self.window_size = window_capacity
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.bind_address)

        self.expected_seq = 1
        self.reorder_stash: Dict[int, bytes] = {}
        self.session_established = False

    @staticmethod
    def _forge_ack(target_seq: int) -> bytes:
        hdr = PacketHeader(type=3, seq_num=target_seq, length=0, checksum=0)
        hdr.checksum = compute_checksum(hdr / b"")
        return bytes(hdr / b"")

    @staticmethod
    def _decode_datagram(raw: bytes) -> Tuple[Optional[PacketHeader], bytes]:
        if len(raw) < 16:
            return None, b""
        hdr = PacketHeader(raw[:16])
        data = raw[16 : 16 + hdr.length]
        cksum = hdr.checksum
        hdr.checksum = 0
        if cksum != compute_checksum(hdr / data):
            return None, b""
        return hdr, data

    def _deliver_contiguous(self) -> None:
        while self.expected_seq in self.reorder_stash:
            buffered_data = self.reorder_stash.pop(self.expected_seq)
            sys.stdout.buffer.write(buffered_data)
            sys.stdout.flush()
            self.expected_seq += 1

    def _handle_data_packet(self, seq: int, payload: bytes, peer_addr: Tuple[str, int]) -> None:
        if not self.session_established:
            return

        # Silently drop frames beyond current active window
        if seq >= self.expected_seq + self.window_size:
            return

        if seq < self.expected_seq:
            # Duplicate / retransmitted segment
            self.sock.sendto(self._forge_ack(self.expected_seq), peer_addr)
        elif seq == self.expected_seq:
            sys.stdout.buffer.write(payload)
            sys.stdout.flush()
            self.expected_seq += 1
            self._deliver_contiguous()
            self.sock.sendto(self._forge_ack(self.expected_seq), peer_addr)
        else:
            # Out-of-order within receive window
            self.reorder_stash[seq] = payload
            self.sock.sendto(self._forge_ack(self.expected_seq), peer_addr)

    def run(self) -> None:
        try:
            while True:
                raw_pkt, peer_addr = self.sock.recvfrom(2048)
                hdr, payload = self._decode_datagram(raw_pkt)
                if hdr is None:
                    continue

                if hdr.type == 0:  # START
                    if not self.session_established:
                        self.session_established = True
                        self.expected_seq = 1
                        self.reorder_stash.clear()
                    self.sock.sendto(self._forge_ack(1), peer_addr)

                elif hdr.type == 2:  # DATA
                    self._handle_data_packet(hdr.seq_num, payload, peer_addr)

                elif hdr.type == 1:  # END
                    if self.session_established:
                        self.sock.sendto(self._forge_ack(hdr.seq_num + 1), peer_addr)
                        break
        finally:
            self.sock.close()


def receiver(receiver_ip, receiver_port, window_size):
    agent = RTPBaseReceiver(receiver_ip, receiver_port, window_size)
    agent.run()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="The IP address of the host that receiver is running on")
    parser.add_argument("receiver_port", type=int, help="The port number on which receiver is listening")
    parser.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = parser.parse_args()

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
