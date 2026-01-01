import os
import sys
import socket
import threading
import sqlite3
import json
import string
import secrets
import time
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

DB_FILE = "certifying_authority_DB.db"
HOST = ""
PORT = 5005

QUORUM_PEER_SIZE = 6

# ======================
# DB INIT
# ======================

def init_db():
    with open("sample_space.json", "r") as f:
        sample_space = json.load(f)

    con = sqlite3.connect(DB_FILE)
    c = con.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    r = [i[0] for i in c.fetchall()]

    if "CONSUMER_TABLE" not in r:
        c.execute("""CREATE TABLE CONSUMER_TABLE (
            CONSUMER_ID INTEGER PRIMARY KEY,
            CONSUMER_NAME TEXT,
            CONSUMER_PHONE_EMAIL TEXT,
            CONSUMER_PHONE_NUMBER INTEGER,
            STAT BOOLEAN
            )""")
        for i in sample_space["users"]:
            c.execute(
                "INSERT INTO CONSUMER_TABLE (CONSUMER_ID, CONSUMER_NAME, CONSUMER_PHONE_EMAIL, CONSUMER_PHONE_NUMBER, STAT) values (?, ?, ?, ?, ?)",
                (i["id"], i["name"], i["email"], i["ph_no"], 0),
            )

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
        for i in range(1000):
            c.execute(
                "INSERT INTO UTILITY_TABLE (UTILITY_ID, UTILITY_PASS, IP, PORT, N_C, E_C, STAT) values (?, ?, ?, ?, ?, ?, ?)",
                (i, "12345", None, None, None, None, 0),
            )

    if "BASE_METER_TABLE" not in r:
        c.execute("""CREATE TABLE BASE_METER_TABLE (
            BASE_METER_ID INTEGER PRIMARY KEY,
            BASE_METER_PASS TEXT,
            ASSIGNED_ID INTEGER,
            IP TEXT,
            PORT INTEGER,
            SERVING_METERS TEXT,
            QUORUM_VALIDSTION_KEY TEXT,
            QUORUM_SLICE TEXT,
            N_C INTEGER,
            E_C INTEGER,
            STAT BOOLEAN
            )""")
        for i in range(1000):
            c.execute(
                "INSERT INTO BASE_METER_TABLE (BASE_METER_ID, BASE_METER_PASS, ASSIGNED_ID, IP, PORT, SERVING_METERS, QUORUM_VALIDSTION_KEY, QUORUM_SLICE, N_C, E_C, STAT) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (i, "12345", None, None, None, None, None, None, None, None, 0),
            )

    if "QUORUM_MAP" not in r:
        c.execute("""CREATE TABLE QUORUM_MAP (
            BASE_METER TEXT,
            QUORUM_NODE TEXT,
            VALIDATED BOOLEAN DEFAULT FALSE,
            PROPOSED_PEERS TEXT,
            SELECTED_PEERS TEXT,
            STAT BOOLEAN DEFAULT FALSE
            )""")

    if "QUORUM_PEERS_MAP" not in r:
        c.execute("""CREATE TABLE QUORUM_PEERS_MAP (
            BASE_METER TEXT,
            QUORUM_NODE TEXT,
            PEER_NODE TEXT,
            STAT BOOLEAN DEFAULT FALSE
            )""")

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
# crypto utilities are provided by _crypto.py

# ======================
# CLIENT SESSION
# ======================

def client_register(conn, addr, aes_key, data):
    data = data.split(",")
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

    # RSA auth exchange - START
    n_s, e_s, d_s = [CA_N, CA_E, CA_D]
    conn.sendall(aes_encrypt(aes_key, f"{n_s},{e_s}"))

    n_c, e_c = map(
        int,
        aes_decrypt(aes_key, conn.recv(1024)).split(",")
    )
    # RSA auth exchange - END

    sig_s = rsa_sign(d_s, n_s, u_asi_id)
    conn.sendall(aes_encrypt(aes_key, f"{u_asi_id}|{sig_s}"))

    c_msg, c_sig = aes_decrypt(aes_key, conn.recv(1024)).split("|", 1)
    print(c_msg, c_sig)

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
    print("[✓] "+("Utility" if client_type == "UTILITY" else "Base Meter")+f" {uid} authenticated")
    conn.close()

def node_secondary_requests_validation(data):
    c_msg, c_sig = data.split("|", 1)
    assigned_id = c_msg.split(",")[0]
    sig = int(c_sig)
    n_c, e_c = None, None

    # Fetch client's public key from DB
    con = sqlite3.connect(DB_FILE)
    c = con.cursor()
    if assigned_id.startswith("u_"):
        c.execute(
            "SELECT N_C, E_C FROM UTILITY_TABLE WHERE ASSIGNED_ID=?",
            (assigned_id,)
        )
    elif assigned_id.startswith("b_"):
        c.execute(
            "SELECT N_C, E_C FROM BASE_METER_TABLE WHERE ASSIGNED_ID=?",
            (assigned_id,)
        )
    row = c.fetchone()
    con.close()
    if row:
        n_c, e_c = row

    if n_c is None or e_c is None:
        return False

    if not rsa_verify(e_c, n_c, c_msg, sig):
        return False
    print("[✓] Client with ASSIGNED_ID", assigned_id, "verified")
    return True

def handle_client(conn, addr):
    # try:
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
    # Client Registration Flow
    if not data.split("|")[-1].isdigit():
        client_register(conn, addr, aes_key, data)
    else:
        # Request contains, assigned id and signature
        if not node_secondary_requests_validation(data):
            print("Client verification failed")
            conn.close()
            return

        head = data.split("|", 1)[0]
        parts = head.split(",", 2)
        assigned_id = parts[0]
        query_type = parts[1]

        if query_type == "INIT":
            # here the server returns a random list of available base meters (a max of 100) and utility (a max of 50) with their port and RSA public keys

            # Fetch available base meters and utilities
            con = sqlite3.connect(DB_FILE)
            c = con.cursor()
            c.execute("SELECT ASSIGNED_ID FROM BASE_METER_TABLE WHERE STAT=1 AND ASSIGNED_ID != ? ORDER BY RANDOM() LIMIT 100", (assigned_id,))
            base_meters = c.fetchall()
            c.execute("SELECT ASSIGNED_ID FROM UTILITY_TABLE WHERE STAT=1 AND ASSIGNED_ID != ? ORDER BY RANDOM() LIMIT 50", (assigned_id,))
            utilities = c.fetchall()
            con.close()

            # Prepare the response
            response_data = []
            for bm in base_meters:
                response_data.append(f"{bm[0]}")
            for u in utilities:
                response_data.append(f"{u[0]}")

            # Send the response by signing the data and encrypting
            data = str(';'.join(map(str, response_data)))
            sig_s = rsa_sign(CA_D, CA_N, data)
            conn.sendall(aes_encrypt(aes_key, f"{data}|{sig_s}"))
            data = aes_decrypt(aes_key, conn.recv(1024))
            # print("Received Data:", data)
            if not data.split("|")[-1].isdigit():
                client_register(conn, addr, aes_key, data)
            else:
                head = data.split("|", 1)[0]
                selected_nodes = head.split(",")
                response_data = []
                con = sqlite3.connect(DB_FILE)
                c = con.cursor()

                quorum_validation_key = random_id(64)
                c.execute(
                    "UPDATE BASE_METER_TABLE SET QUORUM_VALIDSTION_KEY=? WHERE ASSIGNED_ID=?",
                    (quorum_validation_key, assigned_id)
                )
                con.commit()
                response_data.append(f"{quorum_validation_key}")

                # TODO: If it is the first time, mark the STAT of any previously quorum nodes as 0 for this base meter
                c.execute(
                    "UPDATE QUORUM_MAP SET STAT=0 WHERE BASE_METER=?",
                    (assigned_id,)
                )
                con.commit()
                for node_id in selected_nodes:
                    if node_id.startswith("u_"):
                        c.execute("SELECT ASSIGNED_ID, IP, PORT, N_C, E_C FROM UTILITY_TABLE WHERE ASSIGNED_ID=?", (node_id,))
                    elif node_id.startswith("b_"):
                        c.execute("SELECT ASSIGNED_ID, IP, PORT, N_C, E_C FROM BASE_METER_TABLE WHERE ASSIGNED_ID=?", (node_id,))
                    row = c.fetchone()
                    if row:
                        response_data.append(f"{row[0]},{row[1]},{row[2]},{row[3]},{row[4]}")
                        c.execute(
                            "INSERT INTO QUORUM_MAP (BASE_METER, QUORUM_NODE, STAT) VALUES (?, ?, ?)",
                            (assigned_id, row[0], 1)
                        )
                        con.commit()
                con.close()
                data = str(';'.join(map(str, response_data)))
                sig_s = rsa_sign(CA_D, CA_N, data)
                conn.sendall(aes_encrypt(aes_key, f"{data}|{sig_s}"))

        elif query_type == "QUORUM_VALIDATION":
            con = sqlite3.connect(DB_FILE)
            c = con.cursor()
            # check if the key matches the key of the base meter with assigned_id
            head = data.split("|", 1)[0]
            parts = head.split(",")
            c.execute(
                "SELECT * FROM QUORUM_MAP WHERE QUORUM_NODE=? AND BASE_METER=?",
                (assigned_id, parts[2],)
            )
            row1 = c.fetchone()
            c.execute(
                "SELECT QUORUM_VALIDSTION_KEY FROM BASE_METER_TABLE WHERE ASSIGNED_ID=?",
                (parts[2],)
            )
            row2 = c.fetchone()
            if not row1 or not row2 or row2[0] != parts[3]:
                con.close()
                response_data = "ERROR,QUORUM_KEY_INVALID"
                sig_s = rsa_sign(CA_D, CA_N, response_data)
                conn.sendall(aes_encrypt(aes_key, f"{response_data}|{sig_s}"))
                conn.close()
                return
            # update the QUORUM_MAP table to mark respective field as validated
            c.execute(
                "UPDATE QUORUM_MAP SET VALIDATED=1 WHERE BASE_METER=? AND QUORUM_NODE=?",
                (parts[2], assigned_id,)
            )
            con.commit()
            for i in range(10):
                # get list of random QUORUM_PEER_SIZE+1 quorum nodes apart from the current nodes from the QUORUM_MAP table whose VALIDATED is TRUE if not found then make a 1 sec delayed call till 5 times else break and get the ids
                c.execute(
                    "SELECT QUORUM_NODE FROM QUORUM_MAP WHERE BASE_METER=? AND VALIDATED=1 AND QUORUM_NODE!=? ORDER BY RANDOM()",
                    (parts[2], assigned_id,)
                )
                rows = c.fetchall()
                if len(rows) > QUORUM_PEER_SIZE*1.3:
                    break
                time.sleep(1.5)
            if len(rows) > QUORUM_PEER_SIZE*1.3:
                peer_nodes = [row[0] for row in rows][:QUORUM_PEER_SIZE+1]
                c.execute(
                    "UPDATE QUORUM_MAP SET PROPOSED_PEERS=? WHERE BASE_METER=? AND QUORUM_NODE=?",
                    (','.join(peer_nodes), parts[2], assigned_id,)
                )
                con.commit()
                response_data = "SUCCESS,"+(','.join(peer_nodes))
                sig_s = rsa_sign(CA_D, CA_N, response_data)
                conn.sendall(aes_encrypt(aes_key, f"{response_data}|{sig_s}"))

                # receive the list of selected peers from the client
                data = aes_decrypt(aes_key, conn.recv(2048))
                # sign = data.split("|", 1)[-1]
                if not node_secondary_requests_validation(data):
                    print("Client verification failed")
                    conn.close()
                    return
                head = data.split("|", 1)[0]
                selected_peers = head.split(",")[1:]  # first part is assigned_id
                # get the ip, port, n_c, e_c of the selected peers and send it to the client
                peer_info_list = []
                for peer_id in selected_peers:
                    if peer_id.startswith("u_"):
                        # query the DB to get the IP, PORT, N_C, E_C of the peer
                        c.execute(
                            "SELECT IP, PORT, N_C, E_C FROM UTILITY_TABLE WHERE ASSIGNED_ID=?",
                            (peer_id,)
                        )
                    elif peer_id.startswith("b_"):
                        c.execute(
                            "SELECT IP, PORT, N_C, E_C FROM BASE_METER_TABLE WHERE ASSIGNED_ID=?",
                            (peer_id,)
                        )
                    row = c.fetchone()
                    if row:
                        peer_info_list.append(f"{peer_id},{row[0]},{row[1]},{row[2]},{row[3]}")
                        c.execute(
                            "INSERT INTO QUORUM_PEERS_MAP (BASE_METER, QUORUM_NODE, PEER_NODE, STAT) VALUES (?, ?, ?, ?)",
                            (parts[2], assigned_id, peer_id, 0)
                        )
                        con.commit()
                con.close()
                response_data = ';'.join(peer_info_list)
                sig_s = rsa_sign(CA_D, CA_N, response_data)
                conn.sendall(aes_encrypt(aes_key, f"{response_data}|{sig_s}"))
            else:
                response_data = "ERROR,INSUFFICIENT_VALIDATED_NODES"
                con.close()
                sig_s = rsa_sign(CA_D, CA_N, response_data)
                conn.sendall(aes_encrypt(aes_key, f"{response_data}|{sig_s}"))
                conn.close()

        elif query_type == "QUORUM_PEER_VALIDATION":
            con = sqlite3.connect(DB_FILE)
            c = con.cursor()
            # update the QUORUM_PEERS_MAP table to mark respective field as validated
            head = data.split("|", 1)[0]
            parts = head.split(",")
            # TODO - check the qoeum key for verification 
            # check if the peer node exists for the base meter and quorum node
            c.execute(
                "SELECT * FROM QUORUM_PEERS_MAP WHERE BASE_METER=? AND QUORUM_NODE=? AND PEER_NODE=?",
                (parts[2], parts[3], assigned_id,)
            )
            row = c.fetchone()
            if row:
                c.execute(
                "UPDATE QUORUM_PEERS_MAP SET STAT=1 WHERE BASE_METER=? AND QUORUM_NODE=? AND PEER_NODE=?",
                (parts[2], parts[3], assigned_id,)
                )
                con.commit()
                response_data = "SUCCESS"
            else:
                response_data = "ERROR"
            con.close()
            sig_s = rsa_sign(CA_D, CA_N, response_data)
            conn.sendall(aes_encrypt(aes_key, f"{response_data}|{sig_s}"))
        # Miscellaneous operations
        elif query_type == "GET_PUBLIC_KEY":
            # return the RSA public key of the base meter with assigned_id
            con = sqlite3.connect(DB_FILE)
            c = con.cursor()
            head = data.split("|", 1)[0]
            parts = head.split(",")
            # query for both base meter and utility table dependin on the assigned_id prefix
            if parts[2].startswith("u_"):
                c.execute(
                    "SELECT N_C, E_C FROM UTILITY_TABLE WHERE ASSIGNED_ID=?",
                    (parts[2],)
                )
            elif parts[2].startswith("b_"):
                c.execute(
                    "SELECT N_C, E_C FROM BASE_METER_TABLE WHERE ASSIGNED_ID=?",
                    (parts[2],)
                )
            row = c.fetchone()
            con.close()
            if row:
                n_c, e_c = row
                response_data = f"{n_c},{e_c}"
            else:
                response_data = "NOT_FOUND"
            # print("Response Data:", response_data)
            sig_s = rsa_sign(CA_D, CA_N, response_data)
            conn.sendall(aes_encrypt(aes_key, f"{response_data}|{sig_s}"))
        conn.close()
    # except Exception as e:
    #     print("Error:", e)
    #     response_data = "ERROR,CA_SIDE_EXCEPTION"
    #     sig_s = rsa_sign(CA_D, CA_N, response_data)
    #     conn.sendall(aes_encrypt(aes_key, f"{response_data}|{sig_s}"))
    #     conn.close()

# ======================
# SERVER
# ======================

def start_server():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print("Old DB removed")
    else:
        print("DB file not found, proceeding.")
    print("Initializing DB...")
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
            # os.remove(DB_FILE)
            sys.exit()

if __name__ == "__main__":
    start_server()
