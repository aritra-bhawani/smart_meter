import unittest
import socket
import threading
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import _crypto

class DummyConn:
    """A dummy socket-like object for DH tests."""
    def __init__(self):
        self._buffer = []
        self._recv_buffer = []
    def sendall(self, data):
        self._buffer.append(data)
    def recv(self, n):
        if self._recv_buffer:
            return self._recv_buffer.pop(0)
        return b''
    def queue_recv(self, data):
        self._recv_buffer.append(data)

class TestCrypto(unittest.TestCase):
    def test_kdf_aes_key(self):
        key = _crypto.kdf_aes_key(123456789)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 16)

    def test_aes_encrypt_decrypt(self):
        key = _crypto.kdf_aes_key(987654321)
        msg = "Hello, World!"
        enc = _crypto.aes_encrypt(key, msg)
        self.assertIsInstance(enc, bytes)
        dec = _crypto.aes_decrypt(key, enc)
        self.assertEqual(dec, msg)

    def test_validate_aes_channel(self):
        s1, s2 = socket.socketpair()
        key = _crypto.kdf_aes_key(12345)
        def server():
            self.assertTrue(_crypto.validate_aes_channel(s2, key))
            s2.close()
        t = threading.Thread(target=server)
        t.start()
        self.assertTrue(_crypto.validate_aes_channel(s1, key))
        s1.close()
        t.join()

    def test_rsa_generate_sign_verify(self):
        n, e, d = _crypto.rsa_generate()
        msg = "test message"
        sig = _crypto.rsa_sign(d, n, msg)
        self.assertTrue(_crypto.rsa_verify(e, n, msg, sig))
        self.assertFalse(_crypto.rsa_verify(e, n, "other", sig))

    def test_data_enc(self):
        payload = {"a": 1, "b": 2}
        # payload = 3
        h1 = _crypto.data_enc(payload)
        h2 = _crypto.data_enc(payload)
        self.assertEqual(h1, h2)
        self.assertIsInstance(h1, str)
        self.assertEqual(len(h1), 64)

    def test_dh_server_client_exchange(self):
        s1, s2 = socket.socketpair()
        result = {}
        def server():
            result['shared'] = _crypto.dh_server_exchange(s1)
            s1.close()
        t = threading.Thread(target=server)
        t.start()
        shared = _crypto.dh_client(s2)
        t.join()
        s2.close()
        self.assertEqual(result['shared'], shared)

if __name__ == "__main__":
    unittest.main()