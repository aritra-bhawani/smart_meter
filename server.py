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
import sqlite3

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

host=''
port=5000
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connections = {}
try:
	s.bind((host,port))
	print ("SERVER STARTED")
	print ("IP => "+ get_ip())
except socket.error as e:
	print(str(e))

s.listen(10)
print ("port => "+str(s.getsockname()[1]))
print ("listening...\n")

def d_verify(id,key):
	con=sqlite3.connect('data_base.db')
	c = con.cursor()
	c.execute("SELECT * FROM DEVICES where D_ID = ?", (id,))
	result = c.fetchall()
	con.commit()
	con.close()
	print "Initial Device Status in DB : ",result
	if len(result)==0:
		return ([False,"No Device Found By This ID!\nTry again."])
	else:
		if result[0][1]!=key:
			return ([False,"Wrong Credentials!\nTry again."])
		elif result[0][2]!=0:
			return ([False,"Device Already In Use!\nTry again."])
		else:
			return([True,"Device Verified Successfully!\nSharing Key..."])

def d_stat_up(id,val):
	con=sqlite3.connect('data_base.db')
	c = con.cursor()
	c.execute("UPDATE DEVICES SET D_STAT = ? WHERE D_ID = ?", (val,id))
	c.execute("SELECT * FROM DEVICES WHERE D_ID=?",(id,))
	print "Updated Device Status in DB : ",c.fetchall()
	con.commit()
	con.close()
	return True

def verify(conn):
	ar=(conn.recv(1024).rstrip("\n\r")).split(',') #2-2
	print ("Device ID => "+str(ar[0])+"\nDevice Key => "+str(ar[-1]))
	result=d_verify(int(ar[0]),int(ar[-1]))
	if result[0]:
		conn.send(result[1])#3-1
		return ([True,int(ar[0])])
	else:
		conn.send(result[1])#3-1
		connections.pop(id)
		return ([False,int(ar[0])])	

def DHK_exc_s(key,conn):
	sharedPrime=9999999900000001 # a random prime to be chosen
	sharedBase=102124190 # a random number
	conn.send(str(sharedPrime)+","+str(sharedBase)) #5-1
	try:
		A=long(conn.recv(1024).rstrip("\n\r")) #6-2
		B=(sharedBase ** key) % sharedPrime 
	except ValueError:
		connections.pop(id)
		print ("Error Occured!")
		print "Connections List : ",connections
		conn.close()
		print ("Connection with "+str(d_id)+" is Closed")
	conn.send(str(B)) #7-1
	shared_key = (A**key) % sharedPrime
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
	elif q=="d":
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
	h_val = int(hashlib.sha256(string.encode('utf-8')).hexdigest(), 16) % 10**3 #generating 4 bit hash
	if q=="g":
		sg_cal = (h_val**d_e) % n
		# print (h_val)
		return sg_cal
	elif q=="v":
		h_cal = (sg**d_e)%n
		# print (h_val,h_cal)
		if h_val==h_cal : return True
		else : return False

def client_thread(conn,id):
	d_id,key = '',''
	f,e,r = 0,0,0 # flags
	shared_key,serverSecret = '',random.randint(5,20) # used in Diffie-hellman
	n_s,e_s,d = 0,0,0
	n_c,e_c = 0,0 # RSA Signature Parameters of Client

	conn.send('C') #1-1
	while True:
		if f==0:
			# Device Verification
			v=verify(conn)
			time.sleep(.1)
			if v[0]:
				conn.send('S') #4-1
				d_id=v[1]
			else:
				conn.send('F') #4-1
				break

			# Key exchange using Diffie-Helman
			kc=0
			while kc==0:
				shared_key=str(DHK_exc_s(serverSecret,conn))
				# kl=len(shared_key)
				if len(shared_key)==16:
					#checking key symmetricity
					vs=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)]) #generating 32 bit string
					conn.send(enc_dec('e',shared_key,vs+","+vs[::-1])) #8-1 #encrypting and sending the value ("string,reverse of string")
					ar=enc_dec('d',shared_key,conn.recv(1024).rstrip("\n")).split(',') #9-2
					# print ar
					if ar[0]==ar[1][::-1]:
						print("Key Shared and Validated Successfully")	
						kc=1
					else:
						print("Key Validation Failed")
			print ("Shared Key => "+str(shared_key))

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
			if dig_sig_gen('v',e_c,n_c,ar[0],sg=int(ar[1])):
				if d_stat_up(d_id,1):
					f=1
		else:
			data=conn.recv(1024).rstrip("\n\r")
			print ("data received: "+str(data))
			data=enc_dec("d",shared_key,data)
			print ("data retrieved after decrypting: "+data)




			if not data:
				print ("Connection with "+str(d_id)+" is Closed")
				d_stat_up(d_id,0)
				connections.pop(id)
				print "Connections List : ",connections
				conn.close()
				break
	return


while __name__=="__main__":
	try:
		conn , addr = s.accept()
		print('connected to:' +addr[0] +":"+str(addr[1]))

		id = random.randint(1,9999999999)
		start_new_thread(client_thread,(conn,id))

		connections.update({id:conn})
		print "Connections List : ",connections
	except KeyboardInterrupt:
		print ("\nServer is Stopped!")
		sys.exit()	
