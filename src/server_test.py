#!/usr/bin/env python3
"""Tester for the Netpp server (HTTP:1234, Chat:1235, Echo:1236).

Usage:
    python3 client.py                  # run all tests
    python3 client.py -k test_http     # run only the HTTP test
    python3 client.py -k test_chat     # run only the Chat test
    python3 client.py -k test_echo     # run only the Echo test
    python3 client.py -v               # verbose output
"""

import http.client
import os
import signal
import socket
import subprocess
import time
import unittest

HOST = "127.0.0.1"
HTTP_PORT = 1234
CHAT_PORT = 1235
ECHO_PORT = 1236
ECHO_UDP_PORT = 9000

SERVER_BIN = os.path.join(os.path.dirname(__file__), "..", "build", "server")
STARTUP_TIMEOUT = 2.0
RECV_TIMEOUT = 3.0


def _wait_for_port(port: int, timeout: float = STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex((HOST, port)) == 0:
                return True
        time.sleep(0.05)
    return False


class ServerTestCase(unittest.TestCase):
    _server_proc = None

    @classmethod
    def setUpClass(cls):
        path = os.path.realpath(SERVER_BIN)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Server binary not found: {path}")
        cls._server_proc = subprocess.Popen(
            [path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        for port in (HTTP_PORT, CHAT_PORT, ECHO_PORT):
            if not _wait_for_port(port):
                cls._kill_server()
                raise RuntimeError(f"Server did not start listening on port {port}")

    @classmethod
    def tearDownClass(cls):
        cls._kill_server()

    @classmethod
    def _kill_server(cls):
        if cls._server_proc is not None:
            cls._server_proc.send_signal(signal.SIGTERM)
            try:
                cls._server_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls._server_proc.kill()
                cls._server_proc.wait()
            cls._server_proc = None

    # -- HTTP -----------------------------------------------------------
    def test_http(self):
        conn = http.client.HTTPConnection(HOST, HTTP_PORT, timeout=RECV_TIMEOUT)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()

        self.assertIn(resp.status, (200, 404))
        self.assertIn("text/html", resp.getheader("content-type", ""))
        self.assertIn("<html>", body)

    # -- Chat -----------------------------------------------------------
    def test_chat(self):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s1.settimeout(RECV_TIMEOUT)
            s2.settimeout(RECV_TIMEOUT)
            s1.connect((HOST, CHAT_PORT))
            s2.connect((HOST, CHAT_PORT))

            # consume welcome banners
            welcome1 = s1.recv(1024)
            welcome2 = s2.recv(1024)
            self.assertIn(b"Welcome", welcome1)
            self.assertIn(b"Welcome", welcome2)

            # send from s1, expect to receive on s2
            s1.sendall(b"hello\n")
            time.sleep(0.1)
            data = s2.recv(1024)
            self.assertIn(b"hello", data)

            # send from s2, expect to receive on s1
            s2.sendall(b"world\n")
            time.sleep(0.1)
            data = s1.recv(1024)
            self.assertIn(b"world", data)
        finally:
            s1.close()
            s2.close()

    # -- Echo TCP -------------------------------------------------------
    def test_echo_tcp_single(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(RECV_TIMEOUT)
            s.connect((HOST, ECHO_PORT))
            s.sendall(b"hello\n")
            data = s.recv(1024)
            self.assertEqual(data, b"hello\n")

    # -- Echo UDP -------------------------------------------------------
    def test_echo_udp_single(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(RECV_TIMEOUT)
            s.sendto(b"hello\n", (HOST, ECHO_UDP_PORT))
            data, addr = s.recvfrom(1024)
            self.assertEqual(data, b"hello\n")

    def test_echo_udp_multiple(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(RECV_TIMEOUT)
            for msg in [b"aaa", b"bbb", b"ccc"]:
                s.sendto(msg, (HOST, ECHO_UDP_PORT))
                data, _ = s.recvfrom(1024)
                self.assertEqual(data, msg)

    def test_echo_udp_two_clients(self):
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s1,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s2,
        ):
            s1.settimeout(RECV_TIMEOUT)
            s2.settimeout(RECV_TIMEOUT)

            s1.sendto(b"from_s1", (HOST, ECHO_UDP_PORT))
            s2.sendto(b"from_s2", (HOST, ECHO_UDP_PORT))

            d1, _ = s1.recvfrom(1024)
            d2, _ = s2.recvfrom(1024)

            self.assertEqual(d1, b"from_s1")
            self.assertEqual(d2, b"from_s2")


class SignalTestCase(unittest.TestCase):
    """Test that the server shuts down gracefully on signals."""

    def _start_server(self):
        path = os.path.realpath(SERVER_BIN)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Server binary not found: {path}")
        proc = subprocess.Popen(
            [path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        for port in (HTTP_PORT, CHAT_PORT, ECHO_PORT):
            if not _wait_for_port(port):
                proc.kill()
                proc.wait()
                raise RuntimeError(f"Server did not start listening on port {port}")
        return proc

    def _assert_graceful_shutdown(self, proc, sig):
        proc.send_signal(sig)
        try:
            returncode = proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            self.fail(f"Server did not exit within 3s after {sig.name}")
        finally:
            proc.stdout.close()
        self.assertEqual(
            returncode, 0, f"Server exited with code {returncode} after {sig.name}"
        )

    def test_sigint(self):
        proc = self._start_server()
        self._assert_graceful_shutdown(proc, signal.SIGINT)

    def test_sigterm(self):
        proc = self._start_server()
        self._assert_graceful_shutdown(proc, signal.SIGTERM)

    def test_shutdown(self):
        proc = self._start_server()
        # verify server is functional before shutdown
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(RECV_TIMEOUT)
            s.connect((HOST, ECHO_PORT))
            s.sendall(b"ping\n")
            data = s.recv(1024)
            self.assertEqual(data, b"ping\n")
        # now shut down
        self._assert_graceful_shutdown(proc, signal.SIGINT)


if __name__ == "__main__":
    unittest.main()
