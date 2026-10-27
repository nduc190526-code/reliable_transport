import argparse
import socket
import sys
from utils import PacketHeader, compute_checksum

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

HDR_SIZE = 16
MAX_SIZE = 1472

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
        return hdr, payload
    except:
        return None

def receiver(bind_ip, bind_port, win_sz):
    if win_sz < 1:
        raise ValueError("Window size invalid")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, bind_port))

    active_client = None
    next_seq = 1
    buf_store = {}

    try:
        while True:
            raw, src_addr = sock.recvfrom(MAX_SIZE)
            parsed = parse_packet(raw)
            if not parsed:
                continue

            hdr, payload = parsed

            if active_client is None:
                if hdr.type != TYPE_START or hdr.seq_num != 0:
                    continue
                active_client = src_addr
                next_seq = 1
                buf_store.clear()
                sock.sendto(build_packet(TYPE_ACK, 1), active_client)
                continue

            if src_addr != active_client or hdr.type == TYPE_START:
                continue

            if hdr.type == TYPE_END:
                ack_seq = (next_seq + 1) if hdr.seq_num == next_seq else hdr.seq_num
                sock.sendto(build_packet(TYPE_ACK, ack_seq), active_client)
                if hdr.seq_num == next_seq:
                    break
                continue

            if hdr.type != TYPE_DATA:
                continue

            sn = hdr.seq_num

            if sn < next_seq:
                sock.sendto(build_packet(TYPE_ACK, sn), active_client)
                continue

            if sn >= next_seq + win_sz:
                continue

            if sn not in buf_store:
                buf_store[sn] = payload

            while next_seq in buf_store:
                block = buf_store.pop(next_seq)
                sys.stdout.buffer.write(block)
                next_seq += 1

            sys.stdout.flush()
            sys.stdout.buffer.flush()

            sock.sendto(build_packet(TYPE_ACK, sn), active_client)
    finally:
        sock.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("receiver_ip", help="")
    p.add_argument("receiver_port", type=int, help="")
    p.add_argument("window_size", type=int, help="")
    args = p.parse_args()
    receiver(args.receiver_ip, args.receiver_port, args.window_size)

if __name__ == "__main__":
    main()
