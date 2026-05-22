#!/usr/bin/env python3
import socket
import time


def main() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect(('127.0.0.1', 1234))
        except OSError:
            return 1

        sock.sendall(b'AAAAAAAA\n')
        print("Sent: AAAAAAAA")
        time.sleep(1)
        sock.sendall(b'BBBBBBBB\n')
        print("Sent: BBBBBBBB")
        time.sleep(1)
        sock.sendall(b'CCCCCCCC\n')
        print("Sent: CCCCCCCC")
        time.sleep(1)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
