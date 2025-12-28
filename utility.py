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
import string

# For docker
CA_IP = os.getenv("CA_HOST", "ca")     # <— docker service name
CA_PORT = int(os.getenv("CA_PORT", "5005"))

# For normal debugging
# CA_IP = "127.0.0.1"
# CA_PORT = 5005

CA_N = None
CA_E = None

# CLIENT CONFIG START
# UTILITY_ID = int(os.environ["UTILITY_ID"])
UTILITY_PASS = os.getenv("UTILITY_PASS", "12345")
UTILITY_ID = random.randint(1, 1000)
# UTILITY_PASS = "12345"
# ASSIGNED_ID = None
# CLIENT CONFIG END

# ======================
# Load primes
# ======================
with open("prime.json", "r") as f:
    PRIMES = json.load(f)
PRIMES_SMALL = PRIMES["small"]
PRIMES_BIG = PRIMES["big"]

# ======================
# CRYPTO
# ======================

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
	prime, base = map(int, sock.recv(1024).decode().split(",", 1))
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

# ======================
# CLIENT FLOW
# ======================

def get_container_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))   # no packets sent
    ip = s.getsockname()[0]
    s.close()
    return ip

def connect_to_ca():
	sock = socket.socket()
	sock.connect((CA_IP, CA_PORT))

	shared_int = dh_client(sock)
	aes_key = kdf_aes_key(shared_int)

	probe = aes_decrypt(aes_key, sock.recv(1024))
	x, y = probe.split(",", 1)
	sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))

	sock.sendall(aes_encrypt(aes_key, f"UTILITY,{UTILITY_ID},{UTILITY_PASS}"))
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
		aes_decrypt(aes_key, sock.recv(1024)).split(",", 1)
	)

	sock.sendall(aes_encrypt(aes_key, f"{CL_N},{CL_E}"))

	aid, sig = aes_decrypt(aes_key, sock.recv(1024)).split("|", 1)
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

	print("Utility authenticated successfully")
	# for name, value in locals().items():
	# 	print(f"  {name}: {value} (Type: {type(value).__name__})")
	sock.close()

def handle_client(conn, addr):
	try:
		print(f"[++] Client connected from {addr}")

		# SERVER - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
		shared_int = dh_server_exchange(conn)
		# print("Shared Integer:", shared_int)
		aes_key = kdf_aes_key(shared_int)
		# print("AES Key:", aes_key.hex())

		if not validate_aes_channel(conn, aes_key):
			conn.close()
			return
		# SERVER - DH Key Exchange | AES Key Derivation | AES Channel Validation - END

		data = aes_decrypt(aes_key, conn.recv(2048))
		client_msg, client_sig = data.split("|", 1)
		c_assigned_id, command, quorum_key = client_msg.split(",", 2)

		if command == "SELECTED":
			# Connecting to CA to get the public key of the client node ============== START
			sock = socket.socket()
			sock.connect((CA_IP, CA_PORT))
			# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
			shared_int = dh_client(sock)
			aes_key = kdf_aes_key(shared_int)

			probe = aes_decrypt(aes_key, sock.recv(2048))
			x, y = probe.split(",", 1)
			sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))
			# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - END
			
			msg = f"{ASSIGNED_ID},GET_PUBLIC_KEY,{c_assigned_id}"
			sock.sendall(
				aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
			)
			data = aes_decrypt(aes_key, sock.recv(2048))
			# print(data)
			ca_msg, ca_sig = data.split("|", 1)
			if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
				print("CA signature verification failed")
				sock.close()
				conn.close()
				return
			client_n, client_e = map(int, ca_msg.split(",", 1))
			sock.close()
			# Connecting to CA to get the public key of the client node ============== END
			# Verfyfy client signature 
			if not rsa_verify(client_e, client_n, client_msg, int(client_sig)):
				print("CA signature verification failed")
				sock.close()
				conn.close()
				return
			# Connecting to CA to validate the quorum key and get the quorum of this node ============ START
			sock = socket.socket()
			sock.connect((CA_IP, CA_PORT))
			# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
			shared_int = dh_client(sock)
			aes_key = kdf_aes_key(shared_int)

			probe = aes_decrypt(aes_key, sock.recv(2048))
			x, y = probe.split(",", 1)
			sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))
			# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - END
			# Send quorum key for validation
			msg = f"{ASSIGNED_ID},VALIDATE_QUORUM_KEY,{c_assigned_id},{quorum_key}"
			sock.sendall(
				aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
			)
			data = aes_decrypt(aes_key, sock.recv(2048))
			print(data)
			ca_msg, ca_sig = data.split("|", 1)

			sock.close()

		conn.close()

	except Exception as e:
		print("Error:", e)
		conn.close()

def start_server():
	sock = socket.socket()
	sock.bind(("0.0.0.0", 0))
	sock.listen(5)
	global HOST, PORT
	HOST = get_container_ip()
	PORT = sock.getsockname()[1]
	print(f"[+] Utility Server listening on {HOST}:{PORT}")
	while True:
		conn, addr = sock.accept()
		threading.Thread(
			target=handle_client,
			args=(conn, addr),
			daemon=True
		).start()

if __name__ == "__main__":
    connect_to_ca()