import random
import hashlib
import base64
import json
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization as _serial

# ─────────────────────────────────────────────────────────────────────────────
# Key agreement: X25519 (replaces finite-field Diffie–Hellman)
# Signatures:    Ed25519 (replaces RSA-2048 PKCS#1 v1.5)
#
# Wire/API compatibility note:
#   The rest of the system threads public keys as an integer pair (n, e) and
#   parses them with int(). To avoid touching every call site, an Ed25519 public
#   key (32 raw bytes) is encoded as a 256-bit big-endian integer and carried in
#   BOTH the `n` and `e` slots (they are identical). `d` is the raw private key
#   as a hex string — used only locally for signing, never sent on the wire.
#   The shared X25519 secret (32 bytes) is likewise returned as an int so the
#   existing kdf_aes_key(shared_int) continues to work unchanged.
# ─────────────────────────────────────────────────────────────────────────────

_RAW_PUB = dict(encoding=_serial.Encoding.Raw, format=_serial.PublicFormat.Raw)
_RAW_PRIV = dict(encoding=_serial.Encoding.Raw, format=_serial.PrivateFormat.Raw,
                 encryption_algorithm=_serial.NoEncryption())


def kdf_aes_key(shared_int: int) -> bytes:
    return hashlib.sha256(str(shared_int).encode()).digest()[:16]


def _recv_line(sock):
    """Read bytes up to and including the first newline; return (before_nl, after_nl)."""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    nl = buf.find(b"\n")
    if nl < 0:
        return buf, b""
    return buf[:nl], buf[nl + 1:]


def dh_server_exchange(conn) -> int:
    # X25519: server sends its public key first, then receives the client's.
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(**_RAW_PUB)
    conn.sendall(pub.hex().encode() + b"\n")

    client_line, _ = _recv_line(conn)
    client_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(client_line.decode()))
    shared = priv.exchange(client_pub)
    return int.from_bytes(shared, "big")


def dh_client(sock) -> tuple:
    # X25519: receive server public key, then send ours. Any bytes received past
    # the server's key line are returned as `leftover` (preserves the previous
    # piggyback contract; in practice this is empty for the X25519 flow).
    server_line, leftover = _recv_line(sock)
    server_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(server_line.decode()))

    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(**_RAW_PUB)
    sock.sendall(pub.hex().encode() + b"\n")

    shared = priv.exchange(server_pub)
    return int.from_bytes(shared, "big"), leftover


def aes_encrypt(key: bytes, msg: str) -> bytes:
    # AES-128-GCM AEAD: 12-byte nonce, 16-byte tag prepended for authentication
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(nonce + tag + ct)


def aes_decrypt(key: bytes, data: bytes) -> str:
    raw = base64.b64decode(data)
    nonce = raw[:12]
    tag = raw[12:28]
    ct = raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()
    # If decrypt_and_verify raises ValueError, authentication failed.


def validate_aes_channel(conn, aes_key: bytes) -> bool:
    probe = ''.join(random.choices(string.ascii_letters, k=16))
    conn.sendall(aes_encrypt(aes_key, f"{probe},{probe[::-1]}"))
    resp = aes_decrypt(aes_key, conn.recv(1024))
    a, b = resp.split(",", 1)
    return a == b[::-1]


def rsa_generate() -> tuple:
    # Ed25519 keypair, exposed through the legacy (n, e, d) shape.
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(**_RAW_PUB)        # 32 bytes
    priv_bytes = priv.private_bytes(**_RAW_PRIV)                  # 32 bytes
    n = int.from_bytes(pub_bytes, "big")   # public key encoded as a 256-bit int
    e = n                                  # duplicate of n, kept for (n, e) API/wire compat
    d = priv_bytes.hex()                   # opaque local signing handle (never transmitted)
    return n, e, d


def rsa_sign(d, n, msg) -> str:
    # d: hex of the 32-byte Ed25519 private key; n: unused, kept for API compat
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d))
    sig = priv.sign(msg.encode())
    return sig.hex()


def rsa_verify(e, n, msg, sig) -> bool:
    # n carries the Ed25519 public key as a 256-bit int; e is the same value.
    # sig: hex string.
    try:
        pub_bytes = int(n).to_bytes(32, "big")
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(bytes.fromhex(sig), msg.encode())
        return True
    except Exception:
        return False


def data_enc(payload) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()
