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
	
while __name__=="__main__":
	f=0 # flags
	shared_key,clientSecret ="",random.randint(5,20) # used in Diffie-hellman
	n_c,e_c,d=0,0,0
	n_s,e_s=0,0
	response=sock.recv(1024).rstrip("\n") #1-2

	if f==0 and response=='C':
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
		print ("***** Hereafter, All the Data Tranfer Will Be Encrypted. But for Our Convinience, Decrypted Values Will be Printed *****")
		print ("Generating Parameters for Digital Signature...(Wait)")
		ti=time.time()
		n_c,e_c,d = dig_sig_para()
		print ("time taken to generate parameters : "+str(time.time()-ti))
		print("Signing Parameters of Client : \n n (client) => "+str(n_c)+"\n e (client) => "+str(e_c)+"\n d (client:private key) => "+str(d))
		ar=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")).split(',') #10-2
		sock.send(enc_dec('e',shared_key,str(n_c)+","+str(e_c))) #11-1
		n_s,e_s=int(ar[0]),int(ar[1])

		ar=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")).split(',') #12-2
		if not dig_sig_gen('v',e_s,n_s,ar[0],sg=int(ar[1])):
			print ("ERROR : Occured During Signature Verification")
			sock.close()

		vs=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
		sg=dig_sig_gen('g',d,n_c,vs)
		sock.send(enc_dec('e',shared_key,vs+","+str(sg))) #13-1

		print ("Transmission Data Format => start_time,stop_time,unit_slab,signature")
		print ("Operation Successful!\nStarting Data Transmission...")
		print("\n")
		old_hash_value,n_t_id='abc',1 # to be fetched from the local DB(Local Ledger)
		start_time,stop_time,unit_slab=time.time(),0,0
	while True:
		try:
			print("Sending New Token ID => "+str(n_t_id))
			sock.send(enc_dec("e",shared_key,str(n_t_id))) #a-1
			data=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")) #b-2
			print ("Received Hash Value => "+data)
			if old_hash_value!=data:
				print("Old Hash Verification : Failed")
				break
			print ("Old Hash Verification : Successful")	

			# Data Reading
			unit_slab=random.randint(1,50) #to be received from meter
			time.sleep(random.randint(1,5))#function will go here
			stop_time=time.time()

			# Data Sending
			s=str(n_t_id)+','+str(start_time)+','+str(stop_time)+','+str(unit_slab)
			data=s+'|'+str(dig_sig_gen('g',d,n_c,s))
			print("Data to be Transmitted => "+data)
			data=enc_dec("e",shared_key,data)
			print ("Transmitted Cypher : "+data)
			sock.send(data) #c-1

			new_hash_value = int(hashlib.sha256((s+old_hash_value).encode('utf-8')).hexdigest(), 16) % 10**16

			data=enc_dec('d',shared_key,sock.recv(1024).rstrip("\n")) #d-2
			data=data.split('|')
			print ('Received New Hash Value => '+data[0])

			if (dig_sig_gen('v',e_s,n_s,data[0],int(data[1]))) and (str(new_hash_value)==data[0]):
				print ("Signature and New Hash Verification : Successful")
				old_hash_value,n_t_id=data[0],n_t_id+1

			print('Delay Time => '+str(stop_time-start_time)+"\n")
			start_time=stop_time


		except KeyboardInterrupt:
			print ("\nConnection to The Server is Terminated!")
			sys.exit()	

