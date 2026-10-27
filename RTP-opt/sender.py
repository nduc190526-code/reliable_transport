import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

START = 0
END = 1
DATA = 2
ACK = 3

HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5


def make_packet(packet_type, seq_num, payload=b""):
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0
    )
    packet = header / payload
    header.checksum = compute_checksum(packet)
    return bytes(header / payload)


def parse_packet(raw):
    if len(raw) < HEADER_SIZE:
        return None

    try:
        header = PacketHeader(raw[:HEADER_SIZE])
        payload = raw[HEADER_SIZE:HEADER_SIZE + header.length]

        if len(payload) != header.length:
            return None

        received_checksum = header.checksum
        header.checksum = 0

        if compute_checksum(header / payload) != received_checksum:
            return None

        return header
    except (ValueError, TypeError, IndexError):
        return None


def sender(receiver_ip, receiver_port, window_size):
    if window_size < 1:
        raise ValueError("window_size must be at least 1")

    address = (receiver_ip, receiver_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        message = sys.stdin.buffer.read()

        start_packet = make_packet(START, 0)
        sock.sendto(start_packet, address)

        while True:
            try:
                raw, _ = sock.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                sock.sendto(start_packet, address)
                continue

            packet = parse_packet(raw)
            if packet is not None and packet.type == ACK:
                if packet.seq_num == 1:
                    break

        chunks = [
            message[i:i + MAX_PAYLOAD_SIZE]
            for i in range(0, len(message), MAX_PAYLOAD_SIZE)
        ]

        packets = {
            i + 1: make_packet(DATA, i + 1, chunk)
            for i, chunk in enumerate(chunks)
        }

        base = 1
        next_seq = 1
        total_packets = len(chunks)
        acked = {}
        timer_start = None

        while base <= total_packets:
            while (
                next_seq <= total_packets
                and next_seq < base + window_size
            ):
                sock.sendto(packets[next_seq], address)
                if timer_start is None:
                    timer_start = time.monotonic()
                next_seq += 1

            remaining = (
                TIMEOUT - (time.monotonic() - timer_start)
                if timer_start is not None
                else TIMEOUT
            )

            sock.settimeout(max(remaining, 0.001))

            try:
                raw, _ = sock.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                for seq in range(base, next_seq):
                    if not acked.get(seq, False):
                        sock.sendto(packets[seq], address)
                timer_start = time.monotonic()
                continue

            packet = parse_packet(raw)
            if packet is None or packet.type != ACK:
                continue

            ack_num = packet.seq_num
            if base <= ack_num < next_seq:
                acked[ack_num] = True
                old_base = base

                while base < next_seq and acked.get(base, False):
                    del acked[base]
                    base += 1

                if base == next_seq:
                    timer_start = None
                elif base > old_base:
                    timer_start = time.monotonic()

        end_seq = total_packets + 1
        end_packet = make_packet(END, end_seq)
        expected_ack = end_seq + 1

        sock.sendto(end_packet, address)
        deadline = time.monotonic() + TIMEOUT

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            sock.settimeout(max(remaining, 0.001))

            try:
                raw, _ = sock.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                break

            packet = parse_packet(raw)
            if (
                packet is not None
                and packet.type == ACK
                and packet.seq_num == expected_ack
            ):
                break

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="")
    parser.add_argument("receiver_port", type=int, help="")
    parser.add_argument("window_size", type=int, help="")
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()