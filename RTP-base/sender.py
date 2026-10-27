import argparse
import socket
import sys
import time
from utils import PacketHeader, compute_checksum

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

HDR_SIZE = 16
MAX_SIZE = 1472
PAYLOAD_SIZE = MAX_SIZE - HDR_SIZE
TIMEOUT_VAL = 0.5

def build_packet(p_type, seq_num, body=b""):
    hdr = PacketHeader(type=p_type, seq_num=seq_num, length=len(body), checksum=0)
    hdr.checksum = compute_checksum(hdr / body)
    return bytes(hdr / body)

def parse_packet(buf):
    if len(buf) < HDR_SIZE:
        return None
    try:
        hdr = PacketHeader(buf[:HDR_SIZE])
        payload = buf[HDR_SIZE:HDR_SIZE + hdr.length]
        if len(payload) != hdr.length:
            return None
        csum = hdr.checksum
        hdr.checksum = 0
        if compute_checksum(hdr / payload) != csum:
            return None
        return hdr
    except:
        return None

def sender(dest_ip, dest_port, win_sz):
    if win_sz < 1:
        raise ValueError("Window size invalid")

    target = (dest_ip, dest_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_VAL)

    try:
        data_in = sys.stdin.buffer.read()
        pkt_init = build_packet(TYPE_START, 0)
        sock.sendto(pkt_init, target)

        while True:
            try:
                r_buf, _ = sock.recvfrom(MAX_SIZE)
            except socket.timeout:
                sock.sendto(pkt_init, target)
                continue
            res = parse_packet(r_buf)
            if res and res.type == TYPE_ACK and res.seq_num == 1:
                break

        chunks = [data_in[i:i + PAYLOAD_SIZE] for i in range(0, len(data_in), PAYLOAD_SIZE)]
        pkts = {i + 1: build_packet(TYPE_DATA, i + 1, chunks[i]) for i in range(len(chunks))}

        base = 1
        curr = 1
        total = len(chunks)
        t_start = None

        while base <= total:
            while curr <= total and curr < base + win_sz:
                sock.sendto(pkts[curr], target)
                if t_start is None:
                    t_start = time.monotonic()
                curr += 1

            t_left = (TIMEOUT_VAL - (time.monotonic() - t_start)) if t_start else TIMEOUT_VAL
            sock.settimeout(max(t_left, 0.001))

            try:
                r_buf, _ = sock.recvfrom(MAX_SIZE)
            except socket.timeout:
                for s in range(base, curr):
                    sock.sendto(pkts[s], target)
                t_start = time.monotonic()
                continue

            res = parse_packet(r_buf)
            if not res or res.type != TYPE_ACK:
                continue

            ack_id = res.seq_num
            if base < ack_id <= curr:
                base = ack_id
                t_start = None if base == curr else time.monotonic()

        fin_seq = total + 1
        fin_pkt = build_packet(TYPE_END, fin_seq)
        ack_needed = fin_seq + 1
        sock.sendto(fin_pkt, target)
        deadline = time.monotonic() + TIMEOUT_VAL

        while time.monotonic() < deadline:
            sock.settimeout(max(deadline - time.monotonic(), 0.001))
            try:
                r_buf, _ = sock.recvfrom(MAX_SIZE)
            except socket.timeout:
                break
            res = parse_packet(r_buf)
            if res and res.type == TYPE_ACK and res.seq_num == ack_needed:
                break

    finally:
        sock.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("receiver_ip", help="")
    p.add_argument("receiver_port", type=int, help="")
    p.add_argument("window_size", type=int, help="")
    args = p.parse_args()
    sender(args.receiver_ip, args.receiver_port, args.window_size)

if __name__ == "__main__":
    main()
