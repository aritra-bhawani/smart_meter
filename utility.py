import socket
import random
import hashlib
import base64
import json
import math
from Crypto.Cipher import AES

HOST = "127.0.0.1"
PORT = 5005

UTILITY_ID = 66
UTILITY_PASS = "12345"

# ======================
# Load primes
# ======================
with open("prime.json", "r") as f:
    PRIMES_SMALL = json.load(f)["small"]

# ======================
# CRYPTO
# ======================

def kdf_aes_key(shared_int: int) -> bytes:
    return hashlib.sha256(str(shared_int).encode()).digest()[:16]


def dh_client(sock):
    prime, base = map(int, sock.recv(1024).decode().split(","))
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

# ======================
# CLIENT FLOW
# ======================

sock = socket.socket()
sock.connect((HOST, PORT))

shared_int = dh_client(sock)
aes_key = kdf_aes_key(shared_int)

probe = aes_decrypt(aes_key, sock.recv(1024))
x, y = probe.split(",")
sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))

sock.sendall(aes_encrypt(aes_key, f"UTILITY,{UTILITY_ID},{UTILITY_PASS}"))
resp = aes_decrypt(aes_key, sock.recv(1024))
if resp != "OK":
    print("Authentication failed:", resp)
    sock.close()
    exit()

n_c, e_c, d_c = rsa_generate()

n_s, e_s = map(
    int,
    aes_decrypt(aes_key, sock.recv(1024)).split(",")
)

sock.sendall(aes_encrypt(aes_key, f"{n_c},{e_c}"))

msg, sig = aes_decrypt(aes_key, sock.recv(1024)).split(",")
print("TEST:", msg)
sock.sendall(
    aes_encrypt(aes_key, f"{msg},{rsa_sign(d_c, n_c, msg)}")
)

# print(aes_encrypt, n_s, e_s)
print("Utility authenticated successfully")
sock.close()
