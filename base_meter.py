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
	data_enc
)
from _probe import *

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

global QUORUM_SLICE # the meter's own quorum slice with the node ids and their ip and port and public keys and validation status
QUORUM_SLICE = dict()

global SERVING_QUORUM_CONNECTIONS # connections from the quorum nodes to this meter, with their public keys and quorum keys and other info
SERVING_QUORUM_CONNECTIONS = dict()

global PEER_NODE_CONNECTIONS # connections from the peer nodes to this meter, with their public keys and quorum keys and other info
PEER_NODE_CONNECTIONS = dict()

global SERVING_PEER_NODE_CONNECTIONS # connections from the peer nodes to this meter, with their public keys and quorum keys and other info
SERVING_PEER_NODE_CONNECTIONS = dict()

global PEER_CHAIN_STATE  # per-meter hash state used when acting as a peer validator
PEER_CHAIN_STATE = dict()

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
		print(f"[{ASSIGNED_ID}] Error during initial channel setup: {e}")
		return False, None

def connect_to_quorum_node_thread(quorum_key, node_id, node_info):
	try_count = 0
	while try_count < TRY_CYCLE_LIMIT:
		try:
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
			print(f"[{ASSIGNED_ID}] Response from Quorum Node {node_id}: {data}")
			if data.split('|')[0] == "SUCCESS":
				print(f"[{ASSIGNED_ID}] Quorum Node connection validated successfully to {node_id} in {try_count} trie(s)")
				QUORUM_SLICE[node_id]['validated'] = True
				break
			soc.close()
		except Exception as e:
			print(f"[{ASSIGNED_ID}] Error connecting to Quorum Node {node_id}: {e}")
			QUORUM_SLICE[node_id]['validated'] = False
			time.sleep(random.uniform(1, 2.5))
			pass


def connect_to_quorum_node(quorum_key, quorum_slice):
	# for node_id, node_info in quorum_slice.items():
	# 	threading.Thread(
	# 		target=connect_to_quorum_node_thread,
	# 		args=(quorum_key, node_id, node_info),
	# 		daemon=True
	# 	).start()
	# 	time.sleep(random.uniform(0.5, 1))

	threads = []
	for node_id, node_info in quorum_slice.items():
		t = threading.Thread(
			target=connect_to_quorum_node_thread,
			args=(quorum_key, node_id, node_info),
			daemon=True
		)
		t.start()
		threads.append(t)
		time.sleep(random.uniform(0.5, 1))

	# Wait for all peer-connection threads to finish (with a sensible timeout per thread)
	for t in threads:
		try:
			t.join(timeout=10)
		except RuntimeError:
			continue

	all_validated = False
	all_validated = all(
		info.get('validated') is not None for info in QUORUM_SLICE.values()
	)
	print(f"[{ASSIGNED_ID}] Finished connecting to quorum nodes. All validated: {all_validated}")

QUORUM_THRESHOLD = 0.66

def _consult_single_peer(peer_id, peer_info, msg, results, lock):
	try:
		soc = socket.create_connection((peer_info['ip'], int(peer_info['port'])), timeout=10)
		conn_status, aes_key = initial_channel_setup(soc)
		if not conn_status:
			soc.close()
			with lock:
				results[peer_id] = False
			return
		soc.sendall(aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}"))
		soc.settimeout(30)
		resp = aes_decrypt(aes_key, soc.recv(1024))
		with lock:
			results[peer_id] = resp.split("|")[0] == "SUCCESS"
		soc.close()
	except Exception as e:
		print(f"[{ASSIGNED_ID}] Peer consult error {peer_id}: {e}")
		with lock:
			results[peer_id] = False

def consult_peers(c_assigned_id, block_height, reading_timestamp, consumption_value_hash, prev_10m_hash):
	peers = {
		pid: info for pid, info in PEER_NODE_CONNECTIONS.get(c_assigned_id, {}).items()
		if info.get('validated')
	}
	if not peers:
		return 0, 0
	msg = f"{ASSIGNED_ID},PEER_VALIDATE_REQ,{c_assigned_id},{block_height},{reading_timestamp},{consumption_value_hash},{prev_10m_hash}"
	results = {}
	lock = threading.Lock()
	threads = []
	for peer_id, peer_info in peers.items():
		t = threading.Thread(
			target=_consult_single_peer,
			args=(peer_id, peer_info, msg, results, lock),
			daemon=True
		)
		t.start()
		threads.append(t)
	for t in threads:
		t.join(timeout=35)
	agreed = sum(1 for v in results.values() if v)
	return agreed, len(peers)

def _broadcast_meter_req(node_id, node_info, msg, results, lock):
	try:
		soc = socket.create_connection((node_info['ip'], int(node_info['port'])), timeout=10)
		conn_status, aes_key = initial_channel_setup(soc)
		if not conn_status:
			soc.close()
			with lock:
				results[node_id] = False
			return
		soc.sendall(aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}"))
		soc.settimeout(60)
		resp = aes_decrypt(aes_key, soc.recv(1024))
		with lock:
			results[node_id] = resp.split("|")[0] == "SUCCESS"
		soc.close()
	except Exception as e:
		print(f"[{ASSIGNED_ID}] Error sending to {node_id}: {e}")
		with lock:
			results[node_id] = False

def quorum_consensus_init():
	hw = start_meter(base_rate=0.002, variability=0.0001)
	block_height = 0
	prev_10m_hash = "0" * 64

	while True:
		METER_READING_DATA = read_meter(hw)
		print(f"[{ASSIGNED_ID}] Meter Reading: {METER_READING_DATA}")

		block_content = {
			"ledger_id": ASSIGNED_ID,
			"quorum_slice_id": ASSIGNED_ID,
			"block_height": block_height,
			"timestamp": METER_READING_DATA['timestamp'],
			"consumption_value_hash": data_enc(METER_READING_DATA['value']),
			"prev_10m_block_hash": prev_10m_hash
		}
		current_hash = data_enc(block_content)
		consumption_value_hash = block_content["consumption_value_hash"]
		# data_enc(METER_READING_DATA)
		msg = f"{ASSIGNED_ID},METER_REQ,{block_height},{METER_READING_DATA['timestamp']},{METER_READING_DATA['value']},{consumption_value_hash},{prev_10m_hash}"

		results = {}
		lock = threading.Lock()
		validated_nodes = [nid for nid in QUORUM_SLICE if QUORUM_SLICE[nid]['validated'] is True]

		threads = []
		for node_id in validated_nodes:
			t = threading.Thread(
				target=_broadcast_meter_req,
				args=(node_id, QUORUM_SLICE[node_id], msg, results, lock),
				daemon=True
			)
			t.start()
			threads.append(t)
		for t in threads:
			t.join(timeout=65)

		total = len(validated_nodes)
		agreed = sum(1 for v in results.values() if v)
		ratio = agreed / total if total > 0 else 0
		accepted = ratio >= QUORUM_THRESHOLD

		print(f"[{ASSIGNED_ID}] Block {block_height} | consensus: {agreed}/{total} ({ratio*100:.1f}%) | {'ACCEPTED — advancing chain' if accepted else 'REJECTED — block dropped'}")

		if accepted:
			prev_10m_hash = current_hash
			block_height += 1

		time.sleep(30)

def proceed_init():
	print(f"[{ASSIGNED_ID}] proceeding to send INIT...")
	time.sleep(random.randint(10,20))  # simulate delay

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
	random.shuffle(selected)

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

	# global QUORUM_SLICE
	# QUORUM_SLICE = dict()
	for node in nodes:
		parts = node.split(",")
		if len(parts) < 5:
			print("Skipping malformed node entry:", node)
			continue
		node_id, node_ip, node_port, node_n_c, node_e_c = parts[0], parts[1], parts[2], parts[3], parts[4]
		QUORUM_SLICE[node_id] = {'ip': node_ip, 'port': int(node_port), 'n_c': int(node_n_c), 'e_c': int(node_e_c), 'validated': None}

	# the meter will now cooncect to the nodes wiht the ip and port provided
	connect_to_quorum_node(QUORUM_VERIFICATION_KEY, QUORUM_SLICE)
	print(f"[{ASSIGNED_ID}] INIT process completed. With quorum status : {QUORUM_SLICE}")
	# TODO: vlidate the quorum status from the CA

	time.sleep(random.uniform(10, 30))
	quorum_consensus_init()

def connect_to_quorum_peer_thread(c_assigned_id, quorum_key, node_id, node_info):
	try_count = 0
	while try_count < TRY_CYCLE_LIMIT:
		try:
			try_count += 1
			node_ip = node_info['ip']
			node_port = node_info['port']
			soc = socket.create_connection((node_ip, int(node_port)), timeout=10)
			# establish secure AES channel
			conn_status, aes_key = initial_channel_setup(soc)
			if not conn_status:
				soc.close()
				continue

			msg = f"{ASSIGNED_ID},SELECTED_PEER,{c_assigned_id},{quorum_key}"
			soc.sendall(
				aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
			)

			soc.settimeout(60)
			data = aes_decrypt(aes_key, soc.recv(1024))
			print(f"[{ASSIGNED_ID}] Response from Quorum Peer Node {node_id}: {data.split('|')[0]}, {data.split('|')[0] == 'SUCCESS'}")
			if data.split('|')[0] == "SUCCESS":
				print(f"[{ASSIGNED_ID}] Peer Node connection validated successfully to {node_id} in {try_count} trie(s)")
				PEER_NODE_CONNECTIONS[c_assigned_id][node_id]['validated'] = True
				break
			soc.close()
		except Exception as e:
			print(f"[{ASSIGNED_ID}] Error connecting to Quorum Peer Node {node_id}: {e}")
			time.sleep(random.uniform(2, 10))
			pass

def connect_to_quorum_peer(c_assigned_id, quorum_key, peer_connections):
	# for node_id, node_info in peer_connections.items():
	# 	# connect_to_quorum_peer_thread(c_assigned_id, quorum_key, node_id, node_info)
	# 	threading.Thread(
	# 		target=connect_to_quorum_peer_thread,
	# 		args=(c_assigned_id, quorum_key, node_id, node_info),
	# 		daemon=True
	# 	).start()
	# 	time.sleep(random.uniform(0.5, 10))

	# print("--------",c_assigned_id, quorum_key, peer_connections)
	threads = []
	for node_id, node_info in peer_connections.items():
		t = threading.Thread(
			target=connect_to_quorum_peer_thread,
			args=(c_assigned_id, quorum_key, node_id, node_info),
			daemon=True
		)
		t.start()
		threads.append(t)
		time.sleep(random.uniform(0.5, 1))

	# Wait for all peer-connection threads to finish (with a sensible timeout per thread)
	for t in threads:
		try:
			t.join(timeout=10)
		except RuntimeError:
			# If join fails for any reason, continue to the next thread
			continue

	# Check validation status of peer connections for this client (if available)
	all_validated = False
	if c_assigned_id in PEER_NODE_CONNECTIONS:
		all_validated = all(
			info.get('validated', False) for info in PEER_NODE_CONNECTIONS.get(c_assigned_id, {}).values()
		)
	print(f"[{ASSIGNED_ID}] Finished Peer Node validation for {c_assigned_id}. All validated: {all_validated}")


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

	print(f"[{ASSIGNED_ID}] Base Meter authenticated successfully")
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
	print(f"[++][{ASSIGNED_ID}] Client connected from {addr}")

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
			print(f"[{ASSIGNED_ID}] CA signature verification failed")
			response_data = "ERROR"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			sock.close()
			conn.close()
			return
		client_n, client_e = map(int, ca_msg.split(",", 1))
		sock.close()
		# Connecting to CA to get the public key of the client node ============== END
		# Verfyfy client signature
		if not rsa_verify(client_e, client_n, client_msg, int(client_sig)):
			print(f"[{ASSIGNED_ID}] Quorum Client signature verification failed")
			response_data = "ERROR"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			sock.close()
			conn.close()
			return
		SERVING_QUORUM_CONNECTIONS[c_assigned_id] = {'ip': addr[0], 'port': addr[1], 'n_c': client_n, 'e_c': client_e, 'quorum_key': quorum_key, 'last_meter_readings': None, 'last_block_height': None, 'last_timestamp': None, 'last_10m_hash': '0'*64}
		# Connecting to CA to validate the quorum key and get the quorum of this node ============ START
		try_count = 0
		peer_nodes = None
		while try_count < TRY_CYCLE_LIMIT and peer_nodes is None:
			try_count += 1
			sock = socket.socket()
			sock.connect((CA_IP, CA_PORT))
			sock_status, aes_key = initial_channel_setup(sock)
			if not sock_status:
				print(f"[{ASSIGNED_ID}] Failed to establish secure channel with CA for quorum validation")
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
				print(f"[{ASSIGNED_ID}] Quorum validation error from CA: {status_message}")
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
					print(f"[{ASSIGNED_ID}] CA signature verification failed for selected peers")
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
		# Connecting to CA to validate the quorum key and get the quorum of this node ============ END
		# Store peer node connection info
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

		# now make a connection to each peer node in a separate thread to send the quorum key for validation
		connect_to_quorum_peer(c_assigned_id,quorum_key, PEER_NODE_CONNECTIONS[c_assigned_id])

		sock.close()
		response_data = "SUCCESS"
		sig_s = rsa_sign(CL_D, CL_N, response_data)
		conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))

	elif command == "SELECTED_PEER":
		peer_node_assigned_id = client_msg.split(",")[0]
		c_assigned_id = client_msg.split(",")[2]
		quorum_key = client_msg.split(",")[3]
		# Connecting to CA to get the public key of the client node ============== START
		sock = socket.socket()
		sock.connect((CA_IP, CA_PORT))
		conn_status, aes_key = initial_channel_setup(sock)
		if not conn_status:
			sock.close()
			conn.close()
			return

		msg = f"{ASSIGNED_ID},GET_PUBLIC_KEY,{peer_node_assigned_id}"
		sock.sendall(
			aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
		)
		data = aes_decrypt(aes_key, sock.recv(2048))

		ca_msg, ca_sig = data.split("|", 1)
		if not rsa_verify(CA_E, CA_N, ca_msg, int(ca_sig)):
			print("CA signature verification failed")
			response_data = "ERROR"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			sock.close()
			conn.close()
			return
		print(f"[{ASSIGNED_ID}] CA returned public key for peer node: {ca_msg}")
		client_n, client_e = map(int, ca_msg.split(",", 1))
		sock.close()
		# Connecting to CA to get the public key of the client node ============== END
		# Verfyfy client signature
		if not rsa_verify(client_e, client_n, client_msg, int(client_sig)):
			print(f"[{ASSIGNED_ID}] Peer Node signature verification failed")
			response_data = "ERROR"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			sock.close()
			conn.close()
			return
		# SERVING_PEER_NODE_CONNECTIONS[c_assigned_id][peer_node_assigned_id]= {'ip': addr[0], 'port': addr[1], 'n_c': client_n, 'e_c': client_e, 'quorum_key': quorum_key}
		SERVING_PEER_NODE_CONNECTIONS.setdefault(c_assigned_id, {})[peer_node_assigned_id] = {
			'ip': addr[0],
			'port': addr[1],
			'n_c': client_n,
			'e_c': client_e,
			'quorum_key': quorum_key
		}

		# print("Serving Peer Node Connections:", SERVING_PEER_NODE_CONNECTIONS)
		try_count = 0
		validation_success = False
		while try_count < TRY_CYCLE_LIMIT and validation_success is False:
			try_count += 1
			sock = socket.socket()
			sock.connect((CA_IP, CA_PORT))
			sock_status, aes_key = initial_channel_setup(sock)
			if not sock_status:
				print(f"[{ASSIGNED_ID}] Failed to establish secure channel with CA for peer quorum validation")
				sock.close()
				break
			# Send quorum key for validation and get peer nodes list in response or error message
			msg = f"{ASSIGNED_ID},QUORUM_PEER_VALIDATION,{c_assigned_id},{peer_node_assigned_id},{quorum_key}"
			sock.sendall(
				aes_encrypt(aes_key, f"{msg}|{rsa_sign(CL_D, CL_N, msg)}")
			)
			data = aes_decrypt(aes_key, sock.recv(2048))
			ca_msg, ca_sig = data.split("|", 1)
			print(f"[{ASSIGNED_ID}] Peer quorum validation status: {ca_msg}")
			if ca_msg == "SUCCESS":
				validation_success = True
				sock.close()
				break
			time.sleep(random.uniform(1,5))
		response_data = "SUCCESS" if validation_success else "ERROR"
		sig_s = rsa_sign(CL_D, CL_N, response_data)
		conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
		# print(f"[{ASSIGNED_ID}] Current Serving Peer Node Connections: {SERVING_PEER_NODE_CONNECTIONS}")

	elif command == "METER_REQ":
		parts = client_msg.split(",")
		block_height = parts[2]
		reading_timestamp = parts[3]
		reading_value = parts[4]
		consumption_value_hash = parts[5]
		prev_10m_hash = parts[6] if len(parts) > 6 else "0" * 64

		# Verify client signature
		client_e = SERVING_QUORUM_CONNECTIONS[c_assigned_id]['e_c']
		client_n = SERVING_QUORUM_CONNECTIONS[c_assigned_id]['n_c']
		if not rsa_verify(client_e, client_n, client_msg, int(client_sig)):
			print(f"[{ASSIGNED_ID}] Meter Node signature verification failed for reading submission")
			response_data = "ERROR"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			conn.close()
			return

		# Part 1: validate chain continuity against stored last hash
		last_hash = SERVING_QUORUM_CONNECTIONS[c_assigned_id].get('last_10m_hash', '0' * 64)
		if prev_10m_hash != last_hash:
			print(f"[{ASSIGNED_ID}] Chain break from {c_assigned_id}: expected ...{last_hash[-8:]} got ...{prev_10m_hash[-8:]}")
			response_data = "REJECTED"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			conn.close()
			return

		# Compute new block hash (not stored yet — deferred to after Part 2)
		block_content = {
			"ledger_id": c_assigned_id,
			"quorum_slice_id": c_assigned_id,
			"block_height": int(block_height),
			"timestamp": reading_timestamp,
			"consumption_value_hash": consumption_value_hash,
			"prev_10m_block_hash": prev_10m_hash
		}
		new_hash = data_enc(block_content)

		# Part 2: consult sub-quorum peers
		agreed, total = consult_peers(c_assigned_id, block_height, reading_timestamp, consumption_value_hash, prev_10m_hash)
		if total > 0:
			peer_ratio = agreed / total
			peer_accepted = peer_ratio >= QUORUM_THRESHOLD
			print(f"[{ASSIGNED_ID}] Block {block_height} peer consensus: {agreed}/{total} ({peer_ratio*100:.1f}%)")
		else:
			peer_accepted = True
			print(f"[{ASSIGNED_ID}] Block {block_height} no peers available — accepting on Part 1 alone")

		if peer_accepted:
			SERVING_QUORUM_CONNECTIONS[c_assigned_id]['last_10m_hash'] = new_hash
			SERVING_QUORUM_CONNECTIONS[c_assigned_id]['last_block_height'] = int(block_height)
			SERVING_QUORUM_CONNECTIONS[c_assigned_id]['last_timestamp'] = reading_timestamp
			print(f"[{ASSIGNED_ID}] Block {block_height} from {c_assigned_id} ACCEPTED — value={reading_value} hash=...{new_hash[-8:]}")
			response_data = "SUCCESS"
		else:
			print(f"[{ASSIGNED_ID}] Block {block_height} from {c_assigned_id} REJECTED by peers")
			response_data = "REJECTED"
		sig_s = rsa_sign(CL_D, CL_N, response_data)
		conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))

	elif command == "PEER_VALIDATE_REQ":
		parts = client_msg.split(",")
		base_meter_id = parts[2]
		block_height = parts[3]
		reading_timestamp = parts[4]
		consumption_value_hash = parts[5]
		prev_10m_hash = parts[6] if len(parts) > 6 else "0" * 64

		# Verify signature of the requesting quorum node
		requester_info = SERVING_PEER_NODE_CONNECTIONS.get(base_meter_id, {}).get(c_assigned_id)
		if not requester_info:
			response_data = "REJECTED"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			conn.close()
			return
		if not rsa_verify(requester_info['e_c'], requester_info['n_c'], client_msg, int(client_sig)):
			print(f"[{ASSIGNED_ID}] Peer validate sig failed from {c_assigned_id} for {base_meter_id}")
			response_data = "REJECTED"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			conn.close()
			return

		# Check peer chain state for this base meter
		last_hash = PEER_CHAIN_STATE.get(base_meter_id, '0' * 64)
		if prev_10m_hash != last_hash:
			print(f"[{ASSIGNED_ID}] Peer chain break for {base_meter_id}: expected ...{last_hash[-8:]} got ...{prev_10m_hash[-8:]}")
			response_data = "REJECTED"
			sig_s = rsa_sign(CL_D, CL_N, response_data)
			conn.sendall(aes_encrypt(aes_key_cli, f"{response_data}|{sig_s}"))
			conn.close()
			return

		block_content = {
			"ledger_id": base_meter_id,
			"quorum_slice_id": base_meter_id,
			"block_height": int(block_height),
			"timestamp": reading_timestamp,
			"consumption_value_hash": consumption_value_hash,
			"prev_10m_block_hash": prev_10m_hash
		}
		new_hash = data_enc(block_content)
		PEER_CHAIN_STATE[base_meter_id] = new_hash
		print(f"[{ASSIGNED_ID}] Peer validated block {block_height} for {base_meter_id} — hash=...{new_hash[-8:]}")
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
	print(f"[{ASSIGNED_ID}] [+] Base Meter Server listening on {HOST}:{PORT}")
	while True:
		conn, addr = sock.accept()
		threading.Thread(
			target=handle_client,
			args=(conn, addr),
			daemon=True
		).start()

if __name__ == "__main__":
    connect_to_ca()