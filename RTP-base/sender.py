import argparse
import socket
import sys
import time
from utils import PacketHeader, compute_checksum

PKT_TYPE_START = 0
PKT_TYPE_END = 1
PKT_TYPE_DATA = 2
PKT_TYPE_ACK = 3

HDR_BYTES = 16
MTU_LIMIT = 1472
PAYLOAD_CAPACITY = MTU_LIMIT - HDR_BYTES
RETRANSMIT_TIMEOUT = 0.5

class RTPSenderChannel:
    def __init__(self, target_host, target_port, win_limit):
        if win_limit < 1:
            raise ValueError("window_size must be at least 1")
        self.endpoint = (target_host, target_port)
        self.win_limit = win_limit
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.settimeout(RETRANSMIT_TIMEOUT)

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
            return p_hdr
        except Exception:
            return None

    def establish_handshake(self):
        init_pkt = self.create_frame(PKT_TYPE_START, 0)
        self.udp_sock.sendto(init_pkt, self.endpoint)
        while True:
            try:
                raw_in, _ = self.udp_sock.recvfrom(MTU_LIMIT)
            except socket.timeout:
                self.udp_sock.sendto(init_pkt, self.endpoint)
                continue
            parsed = self.verify_and_unpack(raw_in)
            if parsed and parsed.type == PKT_TYPE_ACK and parsed.seq_num == 1:
                break

    def transmit_payload(self, stream_data):
        segments = [stream_data[pos:pos + PAYLOAD_CAPACITY] for pos in range(0, len(stream_data), PAYLOAD_CAPACITY)]
        pkt_store = {idx + 1: self.create_frame(PKT_TYPE_DATA, idx + 1, seg) for idx, seg in enumerate(segments)}
        
        base_seq = 1
        curr_seq = 1
        total_segs = len(segments)
        clock_start = None

        while base_seq <= total_segs:
            while curr_seq <= total_segs and curr_seq < base_seq + self.win_limit:
                self.udp_sock.sendto(pkt_store[curr_seq], self.endpoint)
                if clock_start is None:
                    clock_start = time.monotonic()
                curr_seq += 1

            wait_time = (RETRANSMIT_TIMEOUT - (time.monotonic() - clock_start)) if clock_start is not None else RETRANSMIT_TIMEOUT
            self.udp_sock.settimeout(max(wait_time, 0.001))

            try:
                raw_in, _ = self.udp_sock.recvfrom(MTU_LIMIT)
            except socket.timeout:
                for s_num in range(base_seq, curr_seq):
                    self.udp_sock.sendto(pkt_store[s_num], self.endpoint)
                clock_start = time.monotonic()
                continue

            ack_hdr = self.verify_and_unpack(raw_in)
            if not ack_hdr or ack_hdr.type != PKT_TYPE_ACK:
                continue

            ack_val = ack_hdr.seq_num
            if base_seq < ack_val <= curr_seq:
                base_seq = ack_val
                clock_start = None if base_seq == curr_seq else time.monotonic()

        self.teardown_connection(total_segs + 1)

    def teardown_connection(self, fin_seq):
        term_pkt = self.create_frame(PKT_TYPE_END, fin_seq)
        expected_ack_num = fin_seq + 1
        self.udp_sock.sendto(term_pkt, self.endpoint)
        expire_time = time.monotonic() + RETRANSMIT_TIMEOUT

        while time.monotonic() < expire_time:
            self.udp_sock.settimeout(max(expire_time - time.monotonic(), 0.001))
            try:
                raw_in, _ = self.udp_sock.recvfrom(MTU_LIMIT)
            except socket.timeout:
                break
            ack_hdr = self.verify_and_unpack(raw_in)
            if ack_hdr and ack_hdr.type == PKT_TYPE_ACK and ack_hdr.seq_num == expected_ack_num:
                break

    def close(self):
        self.udp_sock.close()

def main():
    cli_parser = argparse.ArgumentParser()
    cli_parser.add_argument("receiver_ip", help="Target receiver IP")
    cli_parser.add_argument("receiver_port", type=int, help="Target receiver port")
    cli_parser.add_argument("window_size", type=int, help="Sliding window size")
    args = cli_parser.parse_args()

    sender_inst = RTPSenderChannel(args.receiver_ip, args.receiver_port, args.window_size)
    try:
        raw_msg = sys.stdin.buffer.read()
        sender_inst.establish_handshake()
        sender_inst.transmit_payload(raw_msg)
    finally:
        sender_inst.close()

if __name__ == "__main__":
    main()
