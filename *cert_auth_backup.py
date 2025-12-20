# from termcolor import colored
# print colored('Initializing Dependencies...','yellow')
import socket, base64, hashlib, random, string, time, os, sys, sqlite3, json
from _thread import *
from Crypto.Cipher import AES

# if __name__=="__main__":
# 	#Intializing 7 Users 
# 	u=[[23,1234],[24,12345],[25,4321],[26,54321],[27,1234],[28,4321],[29,12345]]
# 	con=sqlite3.connect('data_base.db')
# 	c = con.cursor()
# 	c.execute("SELECT name FROM sqlite_master WHERE type='table';")
# 	r = []
# 	for i in c.fetchall():
# 		r.append(i[0])
# 	if "DEVICES" not in r:
# 		c.execute("""CREATE TABLE DEVICES (
# 					D_ID INTEGER PRIMARY KEY,
# 					D_KEY INTEGER,
# 					D_STAT BOOLEAN
# 					)""")
# 		for i in u:
# 			c.execute("INSERT INTO DEVICES (D_ID, D_KEY, D_STAT) values (?, ?, ?)",(i[0],i[1],0))
# 	if "LEDGER" not in r:
# 		c.execute("""CREATE TABLE LEDGER (
# 					SL_NO INTEGER PRIMARY KEY AUTOINCREMENT,
# 					D_ID INTEGER,
# 					START_TIME TIMESTAMP,
# 					STOP_TIME TIMESTAMP,
# 					UNIT_SLAB FLOAT,
# 					HASH TEXT
# 					)""")
# 	con.commit()
# 	con.close()	

def d_verify(d_id,key):
	con=sqlite3.connect('data_base.db')
	c = con.cursor()
	c.execute("SELECT * FROM DEVICES where D_ID = ?", (d_id,))
	result = c.fetchall()
	con.commit()
	con.close()
	print ("Initial Device Status in DB : ",result)
	if len(result)==0:
		return ([False,"No Device Found By This ID!\nTry again."])
	else:
		if result[0][1]!=key:
			return ([False,"Wrong Credentials!\nTry again."])
		elif result[0][2]!=0:
			return ([False,"Device Already In Use!\nTry again."])
		else:
			return([True,"Device Verified Successfully!\nSharing Key..."])

def d_stat_up(d_id,val):
	con=sqlite3.connect('data_base.db')
	c = con.cursor()
	c.execute("UPDATE DEVICES SET D_STAT = ? WHERE D_ID = ?", (val,d_id))
	c.execute("SELECT * FROM DEVICES WHERE D_ID=?",(d_id,))
	print ("Updated Device Status in DB : ",c.fetchall())
	con.commit()
	con.close()
	return True

def d_add(d_id,start_time,stop_time,unit_slab,has):
	con=sqlite3.connect('data_base.db')
	c = con.cursor()
	c.execute("INSERT INTO LEDGER (D_ID, START_TIME, STOP_TIME, UNIT_SLAB, HASH) values (?, ?, ?, ?, ?)",(d_id,start_time,stop_time,unit_slab,has))
	con.commit()
	con.close()

def verify(conn,n_id):
	ar=(conn.recv(1024).rstrip("\n\r")).split(',') #2-2
	print ("Device ID => "+str(ar[0])+"\nDevice Key => "+str(ar[-1]))
	result=d_verify(int(ar[0]),int(ar[-1]))
	if result[0]:
		conn.send(result[1])#3-1
		return ([True,int(ar[0])])
	else:
		conn.send(result[1])#3-1
		connections.pop(n_id)
		return ([False,int(ar[0])])	

def DHK_exc_s(serverSecret,conn,d_id,n_id):
	sharedPrime=9999999900000001 # a random prime to be chosen
	sharedBase=random.randint(100000000,999999999) #102124190 # a random number
	# conn.send(str(sharedPrime)+","+str(sharedBase))
	print(f"{sharedPrime},{sharedBase}", conn)
	conn.sendall(f"{sharedPrime},{sharedBase}".encode("utf-8")) #5-1
	try:
		A=int(conn.recv(1024).decode("utf-8").rstrip("\n\r")) #6-2
		B=(sharedBase ** serverSecret) % sharedPrime 
	except ValueError:
		connections.pop(n_id)
		print ("Error Occured!")
		print ("Connections List : ",connections)
		conn.close()
		print ("Connection with "+str(d_id)+" is Closed")
	conn.send(str(B).encode("utf-8")) #7-1
	shared_key = (A**serverSecret) % sharedPrime
	return shared_key

def enc_dec(q,key,s):
	if q=="e":
		BLOCK_SIZE = 16
		PADDING = '{'
		pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
		EncodeAES = lambda c,s: base64.b64encode(c.encrypt(pad(s)))
		cipher = AES.new(key)
		encode = EncodeAES(cipher, s)
		return encode
	elif q=="d":
		PADDING = '{'
		DecodeAES = lambda c,e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)	
		cipher = AES.new(key)
		decode = DecodeAES(cipher,s)
		return decode

def compute_gcd(x, y): # finding GCD
	smaller=x if(x<y) else y
	for i in range(1, smaller+1):
		if((x%i==0) and (y%i==0)):
			gcd=i
	return gcd

def inverse(x, m): # finding the inverse
	a,b,u=0,m,1
	while x > 0:
		q = b//x # integer division
		x,a,b,u = b%x, u,x, a-q*u
	if b == 1:
		return a%m

def dig_sig_para():
	# two prime numbers
	p,q=97,89 # to be randomly chosen
	n=p*q
	fi=(p-1)*(q-1)
	ar=[]
	for i in range(1,fi):
		if compute_gcd(i, fi) == 1:
			ar.append(i)
	e = ar[random.randint(int(len(ar)/4),len(ar))]
	d = inverse(e,fi)
	return (n,e,d)

def dig_sig_gen(q,d_e,n,string,sg=0):
	h_val = int(hashlib.sha256(string.encode('utf-8')).hexdigest(), 16) % 10**3 #generating 3 bit hash
	if q=="g":
		sg_cal = (h_val**d_e) % n
		# print (h_val)
		return sg_cal
	elif q=="v":
		h_cal = (sg**d_e)%n
		# print (h_val,h_cal)
		if h_val==h_cal : return True
		else : return False

def close_conn(d_id,n_id):
	print ("Token Verification : Failed\nConnection with "+str(d_id)+" is Closed")
	d_stat_up(d_id,0)
	connections.pop(n_id)
	print ("Connections List : ",connections)
	conn.close()

#==========================
def base_node(n_id,conn,d_id,shared_key,n_s,d,n_c,e_c):
	print('base node identified')
	b_n_ar.append(n_id)
	print ("Base Nodes : ",b_n_ar)


def node(n_id,conn,d_id,shared_key,n_s,d,n_c,e_c):
	print('node identified')
	old_hash_value,t_id='abc',0 # To Be Used During Reading Verification
	data=enc_dec('d',shared_key,conn.recv(1024).rstrip("\n\r")).split(',') #14-2
	n_ip,n_port=data[0],data[1]
	print('Received IP and port address : '+n_ip+' & '+n_port+'\nSending list of base nodes')
	conn.send(enc_dec('e',shared_key,','.join(str(x) for x in b_n_ar)))# 15-1
	data=[i.split(':') for i in enc_dec('d',shared_key,conn.recv(1024).rstrip("\n\r")).split('|')] #16-2
	print ('Nominated based nodes along with sharedBase for '+str(n_id)+'|'+str(d_id)+' => '+str(data))
	for i in data:
		connections[int(i[0])].send(enc_dec('e',connections_credentials[int(i[0])]['shared_key'],str(n_id)+','+str(n_ip)+','+str(n_port)+','+str(i[1])+','+str(i[0])))# sending the required crenentials to the respective base_nodes
	print ("Credentials have been sent to the respected Base Nodes")



def client_thread(n_id,conn):
	d_id,key = '',''
	f=0 # flags
	shared_key,serverSecret = '',random.randint(5,20) # used in Diffie-hellman
	n_s,e_s,d = 0,0,0
	n_c,e_c = 0,0 # RSA Signature Parameters of Client

	# Key exchange using Diffie-Helman
	kc=0
	while kc==0:
		shared_key=str(DHK_exc_s(serverSecret,conn,d_id,n_id))
		# kl=len(shared_key)
		if len(shared_key)==16:
			#checking key symmetricity
			vs=''.join([random.choice(string.ascii_letters + string.digits) for n in range(16)]) #generating 16 bit string
			conn.send(enc_dec('e',shared_key,vs+","+vs[::-1])) #8-1 #encrypting and sending the value ("string,reverse of string")
			ar=enc_dec('d',shared_key,conn.recv(1024).rstrip("\n")).split(',') #9-2
			# print ar
			if ar[0]==ar[1][::-1]:
				print("Key Shared and Validated Successfully")	
				kc=1
			else:
				print("Key Validation Failed")
	print("Shared Key => "+str(shared_key))
	print("***** Data Channel To "+str(n_id)+" is Encrypted *****")

	return (1)



	conn.send('C') # 1-1
	while True:
		if f==0:
			# Device Verification
			v=verify(conn,n_id)
			time.sleep(.1)
			if v[0]:
				conn.send('S') # 4-1 - success
				d_id=v[1]
			else:
				conn.send('F') # 4-1 - failed
				break

			# Key exchange using Diffie-Helman
			kc=0
			while kc==0:
				shared_key=str(DHK_exc_s(serverSecret,conn,d_id,n_id))
				# kl=len(shared_key)
				if len(shared_key)==16:
					#checking key symmetricity
					vs=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)]) #generating 16 bit string
					conn.send(enc_dec('e',shared_key,vs+","+vs[::-1])) #8-1 #encrypting and sending the value ("string,reverse of string")
					ar=enc_dec('d',shared_key,conn.recv(1024).rstrip("\n")).split(',') #9-2
					# print ar
					if ar[0]==ar[1][::-1]:
						print("Key Shared and Validated Successfully")	
						kc=1
					else:
						print("Key Validation Failed")
			print("Shared Key => "+str(shared_key))
			print("***** Data Channel To "+str(n_id)+" is Encrypted *****")

			#Computing parameters for generating digital signature using RSA
			print ("Generating Parameters for Digital Signature...(Wait)")

			ti=time.time()
			n_s,e_s,d = dig_sig_para()
			print ("Time Taken to Generate Parameters : "+str(time.time()-ti))
			print("Signing Parameters of Server : \n n (server) => "+str(n_s)+"\n e (server) => "+str(e_s)+"\n d (server:private key) => "+str(d))
			conn.send(enc_dec('e',shared_key,str(n_s)+","+str(e_s))) #10-1
			ar=enc_dec('d',shared_key,conn.recv(1024).rstrip("\n")).split(',') #11-2
			n_c,e_c=int(ar[0]),int(ar[1])

			#Verifying the Signature of Server
			vs=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
			sg=dig_sig_gen('g',d,n_s,vs)
			conn.send(enc_dec('e',shared_key,vs+","+str(sg))) #12-1

			#Verifying the Signature of Client
			ar=enc_dec('d',shared_key,conn.recv(1024).rstrip("\n")).split(',') #13-2
			# print(dig_sig_gen('v',e_c,n_c,ar[0],sg=int(ar[1])))
			if dig_sig_gen('v',e_c,n_c,ar[0],int(ar[1])):
				if d_stat_up(d_id,1):
					connections_credentials.update({n_id:{'d_id':d_id,'shared_key':shared_key,'n_s':n_s,'d':d,'n_c':n_c,'e_c':e_c}})
					print (connections_credentials)
					f=1
					break
	if f!=0:
		#sepecifying node 23, 24, 25 as the base nodes. But it is to be fetched from the DB in the next update.
		node(n_id,conn,d_id,shared_key,n_s,d,n_c,e_c) if d_id not in [23,24,25,26] else base_node(n_id,conn,d_id,shared_key,n_s,d,n_c,e_c) 
	return

#============
def get_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		# doesn't even have to be reachable
		s.connect(('10.255.255.255', 1))
		IP = s.getsockname()[0]
	except:
		IP = '127.0.0.1'
	finally:
		s.close()
	return IP


# ========================vvvvvvvvvvvvvvvvv========================
# initializing the DB for the certifying authority
def cert_auth_db_init():
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
			IP_PORT TEXT,
			QUORUM_SLICE TEXT,
			SERVING_METERS TEXT,
			STAT BOOLEAN
			)""")
		for i in sample_space["meter_ids"]:
			c.execute("INSERT INTO METER_TABLE (METER_ID, CONSUMER_ID, ASSIGNED_ID, ASSIGNED_ACCESS_KEY, IP_PORT, QUORUM_SLICE, STAT) values (?, ?, ?, ?, ?, ?, ?)",(i, None, None, None, None, None , 0))
	if "UTILITY_TABLE" not in r:
		c.execute("""CREATE TABLE UTILITY_TABLE (
			UTILITY_ID INTEGER PRIMARY KEY,
			UTILITY_PASS INTEGER,
			ASSIGNED_ID INTEGER,
			IP_PORT TEXT,
			STAT BOOLEAN
			)""")
		for i in sample_space["utility_table"]:
			c.execute("INSERT INTO UTILITY_TABLE (UTILITY_ID, UTILITY_PASS, IP_PORT, STAT) values (?, ?, ?, ?)",(i["id"], i["pass"], None, 0))
	if "BASE_METER_TABLE" not in r:
		c.execute("""CREATE TABLE BASE_METER_TABLE (
			BASE_METER_ID INTEGER PRIMARY KEY,
			BASE_METER_PASS INTEGER,
			ASSIGNED_ID INTEGER,
			IP_PORT TEXT,
			SERVING_METERS TEXT,
			STAT BOOLEAN
			)""")
		for i in sample_space["base_meter"]:
			c.execute("INSERT INTO BASE_METER_TABLE (BASE_METER_ID, BASE_METER_PASS, ASSIGNED_ID, IP_PORT, SERVING_METERS, STAT) values (?, ?, ?, ?, ?, ?)",(i["id"], i["pass"], None, None, None, 0))		
	con.commit()
	con.close()
# ========================<<<<<<<>>>>>>>>>>========================

if __name__=="__main__":
	# Config START
	port = 5002
	# Config END


	# DB initialization
	cert_auth_db_init()
	
	# Start the host
	host=''
	# connections = {"utility":{}, "base_meters":{}, "meters":{}}
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connections,connections_credentials = {},{}
	try:
		s.bind((host,port))
		print("SERVER STARTED\nIP => "+ get_ip())
	except socket.error as e:
		print(str(e))

	s.listen() #OS default number of connections
	print("port => "+str(s.getsockname()[1])+"\nListening...\n")
	#=======================

	n_id,b_n_ar=1,[]
	while __name__=="__main__":
		try:
			conn , addr = s.accept()
			print('connected to:' +addr[0] +":"+str(addr[1]))
			start_new_thread(client_thread,(n_id,conn))
			connections.update({n_id:conn})
			n_id+=1
			print ("Connections List :",connections)
		except KeyboardInterrupt:
			print ("\nServer is Stopped!")
			os.remove("certifying_authority_DB.db")
			print("Deleted the certifying authority\'s db")
			# print('Resetting device status in the DB')
			# d_id_list=[23,24,25,26,27,28,29]
			# [d_stat_up(i,0) for i in d_id_list]
			sys.exit()
