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
# BASE_METER_ID = int(os.environ["BASE_METER_ID"])
BASE_METER_PASS = os.getenv("BASE_METER_PASS", "12345")
BASE_METER_ID = random.randint(1, 1000)
# BASE_METER_PASS = "12345"
# ASSIGNED_ID = None
# CLIENT CONFIG END

# Quorum Size
METER_COUNT = 8
UTILITY_COUNT = 2

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
    data = sock.recv(1024).decode()
    # print("Received DH params:", data)
    prime, base = map(int, data.split(","))
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
    a, b = resp.split(",")
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

def connect_to_quorum_node(verification_key, quorum_slice):
	for node_id, node_info in quorum_slice.items():
		node_ip = node_info['ip']
		node_port = node_info['port']
		node_n_c = node_info['n_c']
		node_e_c = node_info['e_c']
		
		# try:
		soc = socket.create_connection((node_ip, int(node_port)), timeout=3)

		# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
		shared_int = dh_client(soc)
		aes_key = kdf_aes_key(shared_int)

		probe = aes_decrypt(aes_key, soc.recv(1024))
		x, y = probe.split(",")
		soc.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))
		# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - END

		msg = f"{ASSIGNED_ID},SELECTED,{verification_key}"
		soc.sendall(
			aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
		)

		soc.close()
		# print(f"Connected to quorum node {node_id} at {node_ip}:{node_port}")
		# except Exception as e:
		# 	print(f"Could not connect to quorum node {node_id} at {node_ip}:{node_port}:", e)

def proceed_init():
	print("proceeding to send INIT...")
	time.sleep(random.randint(3,10))  # simulate delay
	# time.sleep(20)  # simulate delay

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

	data = aes_decrypt(aes_key, sock.recv(4096))
	# print(data[-40:])
	ca_msg, ca_sig = data.split("|")
	if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
		print("CA signature verification failed")
		sock.close()
		exit()
	# print(ca_msg)
	utility, base_meters = list(), list()
	for i in (ca_msg.split(";")):
		if i.startswith("u_"):
			utility.append(i)
		else:
			base_meters.append(i)
	utility = random.sample(utility, min(UTILITY_COUNT, len(utility)))
	base_meters = random.sample(base_meters, min(METER_COUNT, len(base_meters)))
	selected = base_meters + utility

	selected_str = ','.join(map(str, selected))
	# sign the actual payload being sent
	sock.sendall(
		aes_encrypt(aes_key, f"{selected_str}|{rsa_sign(CL_D, CL_N, selected_str)}")
	)

	data = aes_decrypt(aes_key, sock.recv(4096))
	ca_msg, ca_sig = data.split("|")
	if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
		print("CA signature verification failed")
		sock.close()
		exit()
	global QUORUM_VERIFICATION_KEY	
	QUORUM_VERIFICATION_KEY, nodes = ca_msg.split(";")[0], ca_msg.split(";")[1:]
	sock.close()

	global QUORUM_SLICE
	QUORUM_SLICE = dict()
	for node in nodes:
		parts = node.split(",")
		if len(parts) < 5:
			print("Skipping malformed node entry:", node)
			continue
		node_id, node_ip, node_port, node_n_c, node_e_c = parts[0], parts[1], parts[2], parts[3], parts[4]
		QUORUM_SLICE[node_id] = {'ip': node_ip, 'port': int(node_port), 'n_c': int(node_n_c), 'e_c': int(node_e_c)}
	# the meter will now cooncect to the nodes wiht the ip and port provided
	connect_to_quorum_node(QUORUM_VERIFICATION_KEY, QUORUM_SLICE)

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

# ======================
# SERVER FLOW
# ======================

def handle_client(conn, addr):
	try:
		print(f"[+] Client connected from {addr}")

		# SERVER - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
		shared_int = dh_server_exchange(conn)
		# print("Shared Integer:", shared_int)
		aes_key = kdf_aes_key(shared_int)
		# print("AES Key:", aes_key.hex())

		if not validate_aes_channel(conn, aes_key):
			conn.close()
			return
		# SERVER - DH Key Exchange | AES Key Derivation | AES Channel Validation - END

		data = aes_decrypt(aes_key, conn.recv(1024))
		c_assigned_id, command, quorum_key = data.split(",")[0], data.split(",")[1], data.split(",")[2]

		if command == "SELECTED":
			# onnecting to CA to get the public key of the client node
			sock = socket.socket()
			sock.connect((CA_IP, CA_PORT))
			# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
			shared_int = dh_client(sock)
			aes_key = kdf_aes_key(shared_int)

			probe = aes_decrypt(aes_key, sock.recv(1024))
			x, y = probe.split(",")
			sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))
			# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - END
			msg = f"{c_assigned_id},GET_PUBLIC_KEY"
			sock.sendall(
				aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
			)
			data = aes_decrypt(aes_key, sock.recv(1024))
			print(data)
			# ca_msg, ca_sig = data.split("|")
			# if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
			# 	print("CA signature verification failed")
			# 	sock.close()
			# 	conn.close()
			# 	return
			# client_n, client_e = map(int, ca_msg.split(","))
			# sock.close()
			# print(f"Obtained public key of client node: N={client_n}, E={client_e}")

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
	print(f"[+] Base Meter Server listening on {HOST}:{PORT}")
	while True:
		conn, addr = sock.accept()
		threading.Thread(
			target=handle_client,
			args=(conn, addr),
			daemon=True
		).start()

if __name__ == "__main__":
    connect_to_ca()