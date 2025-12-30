import random
import hashlib
import base64
import json
import math
from Crypto.Cipher import AES
import string

# Load primes
with open("prime.json", "r") as f:
    PRIMES = json.load(f)
PRIMES_SMALL = PRIMES["small"]
PRIMES_BIG = PRIMES["big"]


def kdf_aes_key(shared_int: int) -> bytes:
    return hashlib.sha256(str(shared_int).encode()).digest()[:16]


def dh_server_exchange(conn):
    prime = random.choice(PRIMES_BIG)
    base = random.randint(10**8, 10**9)
    secret = random.randint(5, 20)

    conn.sendall(f"{prime},{base}".encode())
    A = int(conn.recv(1024).decode())
    B = pow(base, secret, prime)
    conn.sendall(str(B).encode())

    return pow(A, secret, prime)


def dh_client(sock):
    data = sock.recv(1024).decode()
    prime, base = map(int, data.split(",", 1))
    secret = random.randint(5, 20)

    A = pow(base, secret, prime)
    sock.sendall(str(A).encode())

    B = int(sock.recv(1024).decode())
    return pow(B, secret, prime)


def aes_encrypt(key: bytes, msg: str) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    pad = 16 - (len(msg) % 16)
    msg_padded = msg + chr(pad) * pad
    return base64.b64encode(cipher.encrypt(msg_padded.encode()))


def aes_decrypt(key: bytes, data: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    raw = cipher.decrypt(base64.b64decode(data))
    return raw[:-raw[-1]].decode()
    # unpadded = raw[:-raw[-1]]
    # try:
    #     return unpadded.decode()
    # except UnicodeDecodeError:
    #     # provide a clearer error for callers including raw hex (safe for debugging)
    #     raise ValueError(f"Decryption produced non-text bytes (hex): {unpadded.hex()}")


def validate_aes_channel(conn, aes_key: bytes) -> bool:
    probe = ''.join(random.choices(string.ascii_letters, k=16))
    conn.sendall(aes_encrypt(aes_key, f"{probe},{probe[::-1]}"))
    resp = aes_decrypt(aes_key, conn.recv(1024))
    a, b = resp.split(",", 1)
    return a == b[::-1]


def rsa_generate():
    p, q = random.sample(PRIMES_SMALL, 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randint(3, phi - 1)
        if math.gcd(e, phi) == 1:
            break

    d = pow(e, -1, phi)
    return n, e, d


def rsa_sign(d, n, msg):
    h = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % 1000
    return pow(h, d, n)


def rsa_verify(e, n, msg, sig):
    h = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % 1000
    return h == pow(sig, e, n)
