import argparse
import socket
import sys
from utils import PacketHeader, compute_checksum

PKT_TYPE_START = 0
PKT_TYPE_END = 1
PKT_TYPE_DATA = 2
PKT_TYPE_ACK = 3

HDR_BYTES = 16
MTU_LIMIT = 1472

class RTPReceiverChannel:
    def __init__(self, listen_host, listen_port, win_limit):
        if win_limit < 1:
            raise ValueError("window_size must be at least 1")
        self.win_limit = win_limit
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind((listen_host, listen_port))

    def create_frame(self, p_type, sequence, payload=b""):
        hdr = PacketHeader(type=p_type, seq_num=sequence, length=len(payload), checksum=0)
        hdr.checksum = compute_checksum(hdr / payload)
        return bytes(hdr / payload)

    def verify_and_unpack(self, datagram):
        if len(datagram) < HDR_BYTES:
            return None
        try:
            p_hdr = PacketHeader(datagram[:HDR_BYTES])
            content = datagram[HDR_BYTES:HDR_BYTES + p_hdr.length]
            if len(content) != p_hdr.length:
                return None
            csum_origin = p_hdr.checksum
            p_hdr.checksum = 0
            if compute_checksum(p_hdr / content) != csum_origin:
                return None
            return p_hdr, content
        except Exception:
            return None

    def run_receiver(self):
        peer_addr = None
        next_seq_expected = 1
        rx_buffer = {}

        try:
            while True:
                raw_in, sender_addr = self.udp_sock.recvfrom(MTU_LIMIT)
                parsed = self.verify_and_unpack(raw_in)
                if not parsed:
                    continue

                hdr, payload = parsed

                if peer_addr is None:
                    if hdr.type != PKT_TYPE_START or hdr.seq_num != 0:
                        continue
                    peer_addr = sender_addr
                    next_seq_expected = 1
                    rx_buffer.clear()
                    self.udp_sock.sendto(self.create_frame(PKT_TYPE_ACK, next_seq_expected), peer_addr)
                    continue

                if sender_addr != peer_addr or hdr.type == PKT_TYPE_START:
                    continue

                if hdr.type == PKT_TYPE_END:
                    ack_seq = (next_seq_expected + 1) if hdr.seq_num == next_seq_expected else next_seq_expected
                    self.udp_sock.sendto(self.create_frame(PKT_TYPE_ACK, ack_seq), peer_addr)
                    if hdr.seq_num == next_seq_expected:
                        break
                    continue

                if hdr.type != PKT_TYPE_DATA:
                    continue

                seq_num = hdr.seq_num

                if seq_num < next_seq_expected or seq_num >= next_seq_expected + self.win_limit:
                    self.udp_sock.sendto(self.create_frame(PKT_TYPE_ACK, next_seq_expected), peer_addr)
                    continue

                if seq_num not in rx_buffer:
                    rx_buffer[seq_num] = payload

                while next_seq_expected in rx_buffer:
                    chunk = rx_buffer.pop(next_seq_expected)
                    sys.stdout.buffer.write(chunk)
                    next_seq_expected += 1

                sys.stdout.flush()
                sys.stdout.buffer.flush()

                self.udp_sock.sendto(self.create_frame(PKT_TYPE_ACK, next_seq_expected), peer_addr)
        finally:
            self.udp_sock.close()

def main():
    cli_parser = argparse.ArgumentParser()
    cli_parser.add_argument("receiver_ip", help="Receiver binding IP")
    cli_parser.add_argument("receiver_port", type=int, help="Receiver binding port")
    cli_parser.add_argument("window_size", type=int, help="Sliding window size")
    args = cli_parser.parse_args()

    rx_inst = RTPReceiverChannel(args.receiver_ip, args.receiver_port, args.window_size)
    rx_inst.run_receiver()

if __name__ == "__main__":
    main()
