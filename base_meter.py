import os
import socket
import random
import time
import threading
from _crypto import (
	kdf_aes_key,
	dh_server_exchange,
	dh_client,
	aes_encrypt,
	aes_decrypt,
	validate_aes_channel,
	rsa_generate,
	rsa_sign,
	rsa_verify,
)
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

TRY_CYCLE_LIMIT = 3

global PEER_NODE_CONNECTIONS
PEER_NODE_CONNECTIONS = dict()

global SERVING_QUORUM_CONNECTIONS
SERVING_QUORUM_CONNECTIONS = dict()

# Quorum Size
METER_COUNT = 10
UTILITY_COUNT = 3

QUORUM_PEER_SIZE = 5

# ======================
# CLIENT FLOW
# ======================

def get_container_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))   # no packets sent
    ip = s.getsockname()[0]
    s.close()
    return ip

def initial_channel_setup(_socket):
	try:
		# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
		shared_int = dh_client(_socket)
		aes_key = kdf_aes_key(shared_int)

		probe = aes_decrypt(aes_key, _socket.recv(1024))
		x, y = probe.split(",", 1)
		_socket.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))
		# CLIENT - DH Key Exchange | AES Key Derivation | AES Channel Validation - END
		return True, aes_key
	except Exception as e:
		print("Error during initial channel setup:", e)
		return False, None

def connect_to_quorum_node_thread(quorum_key, node_id, node_info):
	try_count = 0
	while try_count < TRY_CYCLE_LIMIT:
		try_count += 1
		node_ip = node_info['ip']
		node_port = node_info['port']
		soc = socket.create_connection((node_ip, int(node_port)), timeout=10)
		# establish secure AES channel
		conn_status, aes_key = initial_channel_setup(soc)
		if not conn_status:
			soc.close()
			continue

		msg = f"{ASSIGNED_ID},SELECTED,{quorum_key}"
		soc.sendall(
			aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
		)
		soc.settimeout(60)
		data = aes_decrypt(aes_key, soc.recv(1024))
		print(f"Response from Quorum Node {node_id}: {data}")
		if data == "SUCCESS":
			break
		soc.close()
		time.sleep(random.uniform(1, 2.5))

def connect_to_quorum_node(quorum_key, quorum_slice):
	for node_id, node_info in quorum_slice.items():
		threading.Thread(
			target=connect_to_quorum_node_thread,
			args=(quorum_key, node_id, node_info),
			daemon=True
		).start()
		time.sleep(random.uniform(0.5, 1))  # wait for threads to finish

def proceed_init():
	print("proceeding to send INIT...")
	time.sleep(random.randint(20,30))  # simulate delay

	sock = socket.socket()
	sock.connect((CA_IP, CA_PORT))

	conn_status, aes_key = initial_channel_setup(sock)
	if not conn_status:
		sock.close()
		exit()

	msg = f"{ASSIGNED_ID},INIT"
	sock.sendall(
		aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
	)

	data = aes_decrypt(aes_key, sock.recv(4096))
	ca_msg, ca_sig = data.split("|", 1)
	if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
		print("CA signature verification failed")
		sock.close()
		exit()

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
	sock.sendall(
		aes_encrypt(aes_key, f"{selected_str}|{rsa_sign(CL_D, CL_N, selected_str)}")
	)

	data = aes_decrypt(aes_key, sock.recv(4096))
	ca_msg, ca_sig = data.split("|", 1)
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

	# shared_int = dh_client(sock)
	# aes_key = kdf_aes_key(shared_int)

	# probe = aes_decrypt(aes_key, sock.recv(1024))
	# x, y = probe.split(",", 1)
	# sock.sendall(aes_encrypt(aes_key, f"{x},{x[::-1]}"))
	conn_status, aes_key = initial_channel_setup(sock)
	if not conn_status:
		sock.close()
		exit()

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
	time.sleep(random.uniform(0.5, 2.0))

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
	# try:
	print(f"[++] Client connected from {addr}")

	# SERVER - DH Key Exchange | AES Key Derivation | AES Channel Validation - START
	shared_int = dh_server_exchange(conn)
	aes_key_cli = kdf_aes_key(shared_int)

	if not validate_aes_channel(conn, aes_key_cli):
		conn.close()
		return
	# SERVER - DH Key Exchange | AES Key Derivation | AES Channel Validation - END

	data = aes_decrypt(aes_key_cli, conn.recv(2048))
	client_msg, client_sig = data.split("|", 1)
	c_assigned_id, command = client_msg.split(",")[0], client_msg.split(",")[1]

	if command == "SELECTED":
		quorum_key = client_msg.split(",")[2]
		# Connecting to CA to get the public key of the client node ============== START
		sock = socket.socket()
		sock.connect((CA_IP, CA_PORT))
		conn_status, aes_key = initial_channel_setup(sock)
		if not conn_status:
			sock.close()
			conn.close()
			return

		msg = f"{ASSIGNED_ID},GET_PUBLIC_KEY,{c_assigned_id}"
		sock.sendall(
			aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
		)
		data = aes_decrypt(aes_key, sock.recv(2048))

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
		SERVING_QUORUM_CONNECTIONS[c_assigned_id] = {'ip': addr[0], 'port': addr[1], 'n_c': client_n, 'e_c': client_e, 'quorum_key': quorum_key}
		# Connecting to CA to validate the quorum key and get the quorum of this node ============ START
		try_count = 0
		peer_nodes = None
		while try_count < TRY_CYCLE_LIMIT and peer_nodes is None:
			try_count += 1
			sock = socket.socket()
			sock.connect((CA_IP, CA_PORT))
			sock_status, aes_key = initial_channel_setup(sock)
			if not sock_status:
				print("Failed to establish secure channel with CA for quorum validation")
				sock.close()
				break
			# Send quorum key for validation and get peer nodes list in response or error message
			msg = f"{ASSIGNED_ID},QUORUM_VALIDATION,{c_assigned_id},{quorum_key}"
			sock.sendall(
				aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
			)
			data = aes_decrypt(aes_key, sock.recv(2048))
			ca_msg, ca_sig = data.split("|", 1)
			status, status_message = ca_msg.split(",", 1)

			if status == "ERROR":
				print(f"Quorum validation error from CA: {status_message}")
				sock.close()
				break
			elif status == "SUCCESS":
				quorum_peer_list = status_message.split(",")[1:]
				# Sending selected peers to quorum node to get the ip and port and public keys
				selected_peers = random.sample(quorum_peer_list, min(QUORUM_PEER_SIZE, len(quorum_peer_list)))
				msg = f"{ASSIGNED_ID},{','.join(selected_peers)}"
				# print(msg)
				sock.sendall(
					aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
				)
				data = aes_decrypt(aes_key, sock.recv(4096))
				ca_msg, ca_sig = data.split("|", 1)
				if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
					print("CA signature verification failed for selected peers")
					sock.close()
					break
				peer_nodes = ca_msg.split(";")
				sock.close()
				break
			time.sleep(random.uniform(0.5, 2))

		if peer_nodes is None:
			response_data = "ERROR"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			sock.close()
			conn.close()
			return

		print(peer_nodes)
		PEER_NODE_CONNECTIONS[c_assigned_id] = dict()
		for pn in peer_nodes:
			parts = pn.split(",")
			node_id, node_ip, node_port, node_n_c, node_e_c = parts[0], parts[1], parts[2], parts[3], parts[4]
			PEER_NODE_CONNECTIONS[c_assigned_id][node_id] = {
				'ip': node_ip,
				'port': int(node_port),
				'n_c': int(node_n_c),
				'e_c': int(node_e_c),
				'validated': False
			}
		print(f"Peer nodes for {c_assigned_id}: {PEER_NODE_CONNECTIONS[c_assigned_id]}")

		sock.close()
		response_data = "SUCCESS"
		sig_s = rsa_sign(CL_D, CL_N, response_data)
		conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))

	conn.close()

	# except Exception as e:
	# 	print("Error:", e)
	# 	conn.close()

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