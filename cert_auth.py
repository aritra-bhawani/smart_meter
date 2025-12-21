import os
import sys
import math
import socket
import threading
import sqlite3
import json
import random
import string
import hashlib
import base64
import secrets
import string
from Crypto.Cipher import AES

DB_FILE = "certifying_authority_DB.db"
HOST = ""
PORT = 5005

# ======================
# Load primes once
# ======================
with open("prime.json", "r") as f:
    PRIMES = json.load(f)
PRIMES_SMALL = PRIMES["small"]
PRIMES_BIG = PRIMES["big"]

# ======================
# DB INIT
# ======================

def init_db():
	with open("sample_space.json", "r") as f:
		sample_space=json.load(f)
	
	con = sqlite3.connect('certifying_authority_DB.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table';")
	r = []
	for i in c.fetchall():
		r.append(i[0])
	if "CONSUMER_TABLE" not in r:
		c.execute("""CREATE TABLE CONSUMER_TABLE (
			CONSUMER_ID INTEGER PRIMARY KEY,
			CONSUMER_NAME TEXT,
			CONSUMER_PHONE_EMAIL TEXT,
			CONSUMER_PHONE_NUMBER INTEGER,
			STAT BOOLEAN
			)""")
		for i in sample_space["users"]:
			c.execute("INSERT INTO CONSUMER_TABLE (CONSUMER_ID, CONSUMER_NAME, CONSUMER_PHONE_EMAIL, CONSUMER_PHONE_NUMBER, STAT) values (?, ?, ?, ?, ?)",(i["id"], i["name"], i["email"], i["ph_no"], 0))
	if "METER_TABLE" not in r:
		c.execute("""CREATE TABLE METER_TABLE (
			METER_ID INTEGER PRIMARY KEY, 
			CONSUMER_ID INTEGER,
			ASSIGNED_ID INTEGER,
			ASSIGNED_ACCESS_KEY TEXT,
			IP TEXT,
			PORT INTEGER,
			QUORUM_SLICE TEXT,
			SERVING_METERS TEXT,
			N_C INTEGER,
			E_C INTEGER,
			STAT BOOLEAN
			)""")
		for i in sample_space["meter_ids"]:
			c.execute("INSERT INTO METER_TABLE (METER_ID, CONSUMER_ID, ASSIGNED_ID, ASSIGNED_ACCESS_KEY, IP, PORT, QUORUM_SLICE, SERVING_METERS, N_C, E_C, STAT) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",(i, None, None, None, None, None, None, None, None, None, 0))
	if "UTILITY_TABLE" not in r:
		c.execute("""CREATE TABLE UTILITY_TABLE (
			UTILITY_ID INTEGER PRIMARY KEY,
			UTILITY_PASS TEXT,
			ASSIGNED_ID INTEGER,
			IP TEXT,
			PORT INTEGER,
			N_C INTEGER,
			E_C INTEGER,
			STAT BOOLEAN
			)""")
		for i in sample_space["utility_table"]:
			c.execute("INSERT INTO UTILITY_TABLE (UTILITY_ID, UTILITY_PASS, IP, PORT, N_C, E_C, STAT) values (?, ?, ?, ?, ?, ?, ?)",(i["id"], i["pass"], None, None, None, None, 0))
	if "BASE_METER_TABLE" not in r:
		c.execute("""CREATE TABLE BASE_METER_TABLE (
			BASE_METER_ID INTEGER PRIMARY KEY,
			BASE_METER_PASS TEXT,
			ASSIGNED_ID INTEGER,
			IP TEXT,
			PORT INTEGER,
			SERVING_METERS TEXT,
			N_C INTEGER,
			E_C INTEGER,
			STAT BOOLEAN
			)""")
		for i in sample_space["base_meter"]:
			c.execute("INSERT INTO BASE_METER_TABLE (BASE_METER_ID, BASE_METER_PASS, ASSIGNED_ID, IP, PORT, SERVING_METERS, N_C, E_C, STAT) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",(i["id"], i["pass"], None, None, None, None, None, None, 0))
	con.commit()
	con.close()

# ======================
# DB OPS
# ======================

def random_id(leng=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(leng))

# for utility start
def verify_utility(uid, upass):
    print("Req Utility:", uid)
    con = sqlite3.connect(DB_FILE)
    c = con.cursor()
    c.execute(
        "SELECT UTILITY_PASS, STAT FROM UTILITY_TABLE WHERE UTILITY_ID=?",
        (uid,)
    )
    row = c.fetchone()
    con.close()

    if not row:
        return False, "Utility not found"
    if row[0] != upass:
        return False, "Invalid credentials"
    if row[1]:
        return False, "Utility already active"
    return True, "OK"

def update_utility_status(uid, status, id=None, ip=None, port=None, n_c=None, e_c=None):
    con = sqlite3.connect(DB_FILE)
    c = con.cursor()
    if status and id is not None:
        c.execute(
            "UPDATE UTILITY_TABLE SET STAT=?, ASSIGNED_ID=? WHERE UTILITY_ID=?",
            (status, id, uid)
        )
    if status and ip is not None:
        c.execute(
            "UPDATE UTILITY_TABLE SET STAT=?, IP=?, PORT=?, N_C=?, E_C=? WHERE UTILITY_ID=?",
            (status, ip, port, n_c, e_c, uid)
        )
    if status != 1:
        c.execute(
            "UPDATE UTILITY_TABLE SET STAT=?, ASSIGNED_ID=? WHERE UTILITY_ID=?",
            (status, None, uid)
        )
    con.commit()
    con.close()
    # for name, value in locals().items():
    #     print(f"  {name}: {value} (Type: {type(value).__name__})")
# for utility end
# for base meter start
def verify_base_meter(uid, upass):
    print("Req Base Meter:", uid)
    con = sqlite3.connect(DB_FILE)
    c = con.cursor()
    c.execute(
        "SELECT BASE_METER_PASS, STAT FROM BASE_METER_TABLE WHERE BASE_METER_ID=?",
        (uid,)
    )
    row = c.fetchone()
    con.close()

    if not row:
        return False, "Base Meter not found"
    if row[0] != upass:
        return False, "Invalid credentials"
    if row[1]:
        return False, "Base Meter already active"
    return True, "OK"

def update_base_meter_status(uid, status, id=None, ip=None, port=None, n_c=None, e_c=None):
    con = sqlite3.connect(DB_FILE)
    c = con.cursor()
    if status and id is not None:
        c.execute(
            "UPDATE BASE_METER_TABLE SET STAT=?, ASSIGNED_ID=? WHERE BASE_METER_ID=?",
            (status, id, uid)
        )
    if status and ip is not None:
        c.execute(
            "UPDATE BASE_METER_TABLE SET STAT=?, IP=?, PORT=?, N_C=?, E_C=? WHERE BASE_METER_ID=?",
            (status, ip, port, n_c, e_c, uid)
        )
    if status != 1:
        c.execute(
            "UPDATE BASE_METER_TABLE SET STAT=?, ASSIGNED_ID=? WHERE BASE_METER_ID=?",
            (status, None, uid)
        )
    con.commit()
    con.close()
# for base meter end
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
# CLIENT SESSION
# ======================

def handle_client(conn, addr):
    try:
        print(f"[+] Client connected from {addr}")
		# DH Key Exchange | AES Key Derivation | AES Channel Validation - START
        shared_int = dh_server_exchange(conn)
        aes_key = kdf_aes_key(shared_int)

        if not validate_aes_channel(conn, aes_key):
            conn.close()
            return
		# DH Key Exchange | AES Key Derivation | AES Channel Validation - END

		# Client Authentication - START
        data = aes_decrypt(aes_key, conn.recv(1024)).split(",")
        # print(data)
        client_type, uid, upass =  data[0], int(data[1]), data[2]

		# Utility Authentication - START
        if client_type == "UTILITY":
            ok, msg = verify_utility(uid, upass)
            conn.sendall(aes_encrypt(aes_key, msg))
            if not ok:
                conn.close()
                return
            u_asi_id = 'u_' + random_id()
            update_utility_status(uid, 1, id=u_asi_id)
		# Utility Authentication - END
		# Base Meter Authentication - START
        if client_type == "BASE_METER":
            ok, msg = verify_base_meter(uid, upass)
            conn.sendall(aes_encrypt(aes_key, msg))
            if not ok:
                conn.close()
                return
            u_asi_id = 'b_' + random_id()
            update_base_meter_status(uid, 1, id=u_asi_id)
		# Base Meter Authentication - END
		# Client Authentication - END

        # RSA auth exchange - START
        n_s, e_s, d_s = [CA_N, CA_E, CA_D]
        conn.sendall(aes_encrypt(aes_key, f"{n_s},{e_s}"))

        n_c, e_c = map(
            int,
            aes_decrypt(aes_key, conn.recv(1024)).split(",")
        )
		# RSA auth exchange - END

        sig_s = rsa_sign(d_s, n_s, u_asi_id)
        conn.sendall(aes_encrypt(aes_key, f"{u_asi_id},{sig_s}"))

        c_msg, c_sig = aes_decrypt(aes_key, conn.recv(1024)).split("|")

        if client_type == "UTILITY":
            if not rsa_verify(e_c, n_c, c_msg, int(c_sig)):
                update_utility_status(uid, 0)
                conn.close()
                return
            else:
                update_utility_status(uid, 1, ip=c_msg.split(":")[0], port=c_msg.split(":")[-1], n_c=n_c, e_c=e_c)
        
        if client_type == "BASE_METER":
            if not rsa_verify(e_c, n_c, c_msg, int(c_sig)):
                update_base_meter_status(uid, 0)
                conn.close()
                return
            else:
                update_base_meter_status(uid, 1, ip=c_msg.split(":")[0], port=c_msg.split(":")[-1], n_c=n_c, e_c=e_c)
        
		# for name, value in locals().items():
        #     print(f"  {name}: {value} (Type: {type(value).__name__})")
        print("[✓] "+("Utility" if client_type == "UTILITY" else "Base Meter") + f" {uid} authenticated")
        conn.close()

    except Exception as e:
        print("Error:", e)
        conn.close()

# ======================
# SERVER
# ======================

def start_server():
    init_db()
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen()
    print("Certifying Authority STARTED at", s.getsockname())
    global CA_N, CA_E, CA_D
    CA_N, CA_E, CA_D = rsa_generate()
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            ).start()
        except KeyboardInterrupt:
            print("\nCertifying Authority STOPPED")
            os.remove(DB_FILE)
            sys.exit()

if __name__ == "__main__":
    start_server()
