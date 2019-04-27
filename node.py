from termcolor import colored
print colored('Initializing Dependencies...','yellow')
import socket
from thread import *
from Crypto.Cipher import AES
import base64
import hashlib
import random
import string
import time
import os
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# host = input('enter IP of server') #192.168.43.212
# port = int(input('enter Port to connect')) #10000
host = '127.0.0.1'
port = 5000
sock.connect((host,port))

def DHK_exc_c(key,sock):
	ar=(sock.recv(1024).rstrip("\n")).split(',') #5-2
	sharedPrime,sharedBase=int(ar[0]),int(ar[1])
	try:
		A = (sharedBase**key) % sharedPrime
		sock.send(str(A)) #6-1
		B=long(sock.recv(1024).rstrip("\n")) #7-2
		shared_key=(B ** key) % sharedPrime
	except ValueError:
		print ("Error Occured!\nTry again")
	return shared_key

def enc_dec(q,key,string):
	if q=="e":
		BLOCK_SIZE = 16
		PADDING = '{'
		pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
		EncodeAES = lambda c,s: base64.b64encode(c.encrypt(pad(s)))
		cipher = AES.new(key)
		encode = EncodeAES(cipher, string)
		return encode
	if q=="d":
		PADDING = '{'
		DecodeAES = lambda c,e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)	
		cipher = AES.new(key)
		decode = DecodeAES(cipher,string)
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
	p,q=79,71 # to be randomly chosen
	n=p*q
	fi=(p-1)*(q-1)
	ar=[]
	for i in range(1,fi):
		if compute_gcd(i, fi) == 1:
			ar.append(i)
	# print ("ar="+str(ar))
	e = ar[random.randint(int(len(ar)/4),len(ar))]
	# print ("e ="+str(e))
	d = inverse(e,fi)
	# print (n,e,d)
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

#=====================NODAL SERVER===================#
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
def nodal_client_thread(n_c_id,conn):
	print base_nodes_d
	while True:
		data=conn.recv(1024).rstrip("\n")
		if data:
			print(data)
		if not data:
			print('closing connection')
			conn.close()
			connections.pop(n_c_id)
def nodal_server_listen(s):
	n_c_id = 1
	while __name__=="__main__":
		try:
			conn , addr = s.accept()
			print('connected to:' +addr[0] +":"+str(addr[1]))
			start_new_thread(nodal_client_thread,(n_c_id,conn))
			connections.update({n_c_id:conn})
			n_c_id+=1
			print "Connections List : ",connections
		except KeyboardInterrupt:
			print ("\nServer is Stopped!")
			break	
#==========================	
if __name__=="__main__":
	n_ip,n_port='','' # port for nodal server
	f=0 # flags
	shared_key,clientSecret ="",random.randint(5,20) # used in Diffie-hellman
	n_c,e_c,d=0,0,0
	n_s,e_s=0,0
	
	b_node_connections={}

	old_hash_value,n_t_id='abc',1 # to be fetched from the local DB(Local Ledger)
	start_time,stop_time,unit_slab=0,0,0 # time stamps ad unit slabs

	response=sock.recv(1024).rstrip("\n") #1-2
	while f==0 and response=='C':
		d_id,key=0,0
		print ("Connection Established")
		while d_id==0:
			d_id=raw_input("Enter Device ID : ")
			try:
				d_id=int(d_id)
				break
			except ValueError:
				print("Enter Valid Device ID!")
				d_id=0
		while key==0:
			key=raw_input("Enter Device Key : ")
			try:
				key=int(key)
				break
			except ValueError:
				print("Enter Valid Device Key!")
				key=0		
		sock.send(str(d_id)+","+str(key)) #2-1
		print (sock.recv(1024).rstrip("\n"))#3-2

		# Key Exchange Process
		if sock.recv(1024).rstrip("\n") != "S": #4-2
			break

		# Key exchange using Diffie-Helman
		kc=0
		while kc==0:
			shared_key=str(DHK_exc_c(clientSecret,sock))
			if len(str(shared_key))==16:
				ar=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")).split(',') #8-2
				# print ar
				if ar[0]==ar[1][::-1]:
					vs = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
					sock.send(enc_dec('e',shared_key,vs+","+vs[::-1])) #9-1
					print("Key Shared and Validated Successfully!")
					kc=1
				else:
					print("Key Validation Failed")		
		print ("Shared Key => "+shared_key) # to be hidden just printed for test purpose		
		print colored("***** Hereafter, All the Data Tranfer Will Be Encrypted. But for Our Convinience, Decrypted Values Will be Printed *****",'red')
		print ("Generating Parameters for Digital Signature...(Wait)")
		ti=time.time()
		n_c,e_c,d = dig_sig_para()
		print ("time taken to generate parameters : "+str(time.time()-ti))
		print("Signing Parameters of Client : \n n (client) => "+str(n_c)+"\n e (client) => "+str(e_c)+"\n d (client:private key) => "+str(d))
		ar=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")).split(',') #10-2
		sock.send(enc_dec('e',shared_key,str(n_c)+","+str(e_c))) #11-1
		n_s,e_s=int(ar[0]),int(ar[1])
		# print (n_s,e_s)

		ar=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")).split(',') #12-2
		# print(dig_sig_gen('v',e_s,n_s,ar[0],sg=int(ar[1])))
		if not dig_sig_gen('v',e_s,n_s,ar[0],sg=int(ar[1])):
			print ("ERROR : Occured During Signature Verification")
			sock.close()

		vs=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
		sg=dig_sig_gen('g',d,n_c,vs)
		sock.send(enc_dec('e',shared_key,vs+","+str(sg))) #13-1

		#====================================
		print ("\nStarting the nodal-server")
		host=''
		n_port=random.randint(5000,15000)
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connections,connections_credentials = {},{}
		try:
			s.bind((host,n_port))
			n_ip=get_ip()
			print colored("NODAL SERVER STARTED\nIP => "+ n_ip,'green')
		except socket.error as e:
			print(str(e))
		s.listen(10)
		print colored("n_port => "+str(s.getsockname()[1])+"\nlistening...\n",'green')
		start_new_thread(nodal_server_listen,(s,))
		time.sleep(1)
		#=====================================

		print ('Sending the IP and Port  no of the nodal-server')
		sock.send(enc_dec("e",shared_key,str(n_ip)+','+str(n_port))) #14-1 
		data=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")).split(',') #15-2
		print ('List of base nodes received from server: '+str(data))
		data=random.sample(data, 2) # selecting 2 random base nodes
		string,base_nodes_d='',{}
		for i in data:
			sharedBase=random.randint(100000000,999999999)
			string+=i+':'+str(sharedBase)+'|'
			base_nodes_d.update({int(i):sharedBase})
		print('Sending the nominated base nodes list along with respective sharedBase for key exchange')
		sock.send(enc_dec("e",shared_key,string[:-1])) #16-1
