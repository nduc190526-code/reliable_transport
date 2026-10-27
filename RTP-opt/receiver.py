import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

START = 0
END = 1
DATA = 2
ACK = 3

HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472


def make_packet(packet_type, seq_num, payload=b""):
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0
    )
    header.checksum = compute_checksum(header / payload)
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

        return header, payload
    except (ValueError, TypeError, IndexError):
        return None


def receiver(receiver_ip, receiver_port, window_size):
    if window_size < 1:
        raise ValueError("window_size must be at least 1")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    connected_address = None
    expected_seq = 1
    buffer = {}

    try:
        while True:
            raw, address = sock.recvfrom(MAX_PACKET_SIZE)
            parsed = parse_packet(raw)

            if parsed is None:
                continue

            header, payload = parsed

            if connected_address is None:
                if header.type != START or header.seq_num != 0:
                    continue

                connected_address = address
                expected_seq = 1
                buffer.clear()

                sock.sendto(make_packet(ACK, 1), connected_address)
                continue

            if address != connected_address:
                continue

            if header.type == START:
                continue

            if header.type == END:
                if header.seq_num == expected_seq:
                    sock.sendto(
                        make_packet(ACK, header.seq_num + 1),
                        connected_address
                    )
                    break

                sock.sendto(
                    make_packet(ACK, header.seq_num),
                    connected_address
                )
                continue

            if header.type != DATA:
                continue

            seq_num = header.seq_num

            if seq_num < expected_seq:
                sock.sendto(make_packet(ACK, seq_num), connected_address)
                continue

            if seq_num >= expected_seq + window_size:
                continue

            if seq_num not in buffer:
                buffer[seq_num] = payload

            while expected_seq in buffer:
                data = buffer.pop(expected_seq)
                sys.stdout.buffer.write(data)
                expected_seq += 1

            sys.stdout.flush()
            sys.stdout.buffer.flush()

            sock.sendto(make_packet(ACK, seq_num), connected_address)

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="")
    parser.add_argument("receiver_port", type=int, help="")
    parser.add_argument("window_size", type=int, help="")
    args = parser.parse_args()

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()