import os
import socket
import random
import hashlib
import base64
import json
import math
from Crypto.Cipher import AES
import time
import threading

# For docker
CA_IP = os.getenv("CA_HOST", "ca")     # <— docker service name
CA_PORT = int(os.getenv("CA_PORT", "5005"))

# For normal debugging
# CA_IP = "127.0.0.1"
# CA_PORT = 5005

CA_N = None
CA_E = None

# CLIENT CONFIG START
# BASE_METER_ID = int(os.environ["BASE_METER_ID"])
BASE_METER_PASS = os.getenv("BASE_METER_PASS", "12345")
BASE_METER_ID = random.randint(1, 1000)
# BASE_METER_PASS = "12345"
# ASSIGNED_ID = None
# CLIENT CONFIG END

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

def rsa_verify(e, n, msg, sig):
    h = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % 1000
    return h == pow(sig, e, n)

# ======================
# CLIENT FLOW
# ======================

def get_container_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))   # no packets sent
    ip = s.getsockname()[0]
    s.close()
    return ip

def proceed_init():
	print("proceeding to send INIT...")
	time.sleep(random.randint(3,10))  # simulate delay

	sock = socket.socket()
	sock.connect((CA_IP, CA_PORT))

	# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
	shared_int = dh_client(sock)
	aes_key = kdf_aes_key(shared_int)

	probe = aes_decrypt(aes_key, sock.recv(1024))
	x, y = probe.split(",")
	sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))
	# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - END

	msg = f"{ASSIGNED_ID},INIT"
	sock.sendall(
		aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
	)

	data = aes_decrypt(aes_key, sock.recv(1024))
	print(data)
	ca_msg, ca_sig = data.split("|")
	if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
		print("CA signature verification failed")
		sock.close()
		exit()
	print(ca_msg)
	for i in (ca_msg.split(";")):
		s = socket.socket()
		s.connect((i.split(",")[1], int(i.split(",")[2])))
	sock.close()

def connect_to_ca():
	sock = socket.socket()
	sock.connect((CA_IP, CA_PORT))

	shared_int = dh_client(sock)
	aes_key = kdf_aes_key(shared_int)

	probe = aes_decrypt(aes_key, sock.recv(1024))
	x, y = probe.split(",")
	sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))

	sock.sendall(aes_encrypt(aes_key, f"BASE_METER,{BASE_METER_ID},{BASE_METER_PASS}"))
	resp = aes_decrypt(aes_key, sock.recv(1024))
	if resp != "OK":
		print("Authentication failed:", resp)
		sock.close()
		exit()

	global CL_N, CL_E, CL_D # Client RSA keys
	CL_N, CL_E, CL_D = rsa_generate()

	# Ensure CA globals are assigned to the module-level variables
	global CA_N, CA_E
	CA_N, CA_E = map(
		int,
		aes_decrypt(aes_key, sock.recv(1024)).split(",")
	)

	sock.sendall(aes_encrypt(aes_key, f"{CL_N},{CL_E}"))

	aid, sig = aes_decrypt(aes_key, sock.recv(1024)).split("|")
	print("ASSIGNED_ID:", aid)
	global ASSIGNED_ID
	ASSIGNED_ID = aid

	threading.Thread(
		target=start_server,
		daemon=False
	).start()
	time.sleep(0.5)

	# Send the server ip and port with
	msg = f"{HOST}:{PORT}"
	sock.sendall(
		aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
	)

	print("Base Meter authenticated successfully")
	# for name, value in locals().items():
	# 	print(f"  {name}: {value} (Type: {type(value).__name__})")
	sock.close()

	# Reconnect to send INIT | selection for random base meter for this operation
	if random.randint(0, 1):
		proceed_init()


def start_server():
	sock = socket.socket()
	sock.bind(("0.0.0.0", 0))
	sock.listen(5)
	global HOST, PORT
	HOST = get_container_ip()
	PORT = sock.getsockname()[1]
	print(f"[+] Base Meter Server listening on {HOST}:{PORT}")
	a = list()
	while True:
		conn, addr = sock.accept()
		a.append(addr)
		print(f"[+] Client connected from {addr}")
		print(f"[+] Current connected clients: {a}")
		conn.close()
		# handlCL_Elient(conn, addr)

if __name__ == "__main__":
    connect_to_ca()