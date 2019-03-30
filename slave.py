import socket
import sys
import time
import random
from Crypto.Cipher import AES
import base64
import os
# import serial

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# host = input('enter IP of server') #192.168.43.212
# port = int(input('enter Port to connect')) #10000
host = '127.0.0.1'
port = 10000
sock.connect((host,port))

'''
    Device ID = 23 or 24
    key = 1234 or 12345
'''

(f,e)=(0,0)
clientSecret=random.randint(5,20)

def DHK_exc_c(key,sock):
	sharedPrime=int(sock.recv(1024).rstrip("\n"))
	sharedBase=int(sock.recv(1024).rstrip("\n"))
	# print (sharedPrime)
	# print (sharedBase)

	A = (sharedBase**key) % sharedPrime #1. calculating A
	sock.send(str(A)) #2. send the value
	B=int(sock.recv(1024).rstrip("\n")) #6. receiving B
	shared_key=(B ** key) % sharedPrime

	# print (shared_key)
	return ([True,shared_key])

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

while True:
	response=sock.recv(1024).rstrip("\n")
	# print response
	shared_key=""
	if f==0 and response=='connected':
		print (sock.recv(1024).rstrip("\n"))
		d_id=str(input())
		sock.send(d_id)

		print(sock.recv(1024).rstrip("\n"))
		key=str(input())
		sock.send(key)

		response_new=sock.recv(1024).rstrip("\n")
		# print response_new
		if response_new=='verified':
			print "Validity Successfully Verified"
			f=1
		else:
			print "Check the credentials and try again!"
			break
		r=DHK_exc_c(clientSecret,sock)
		print (sock.recv(1024).rstrip("\n")) # print success data from server
		print ("Shared Key : ")
		shared_key=str(r[1])
		print (shared_key)
		
	while True:
		# print(shared_key)
		s=str(d_id)+" => "+str(time.time())+" => "+str(random.randint(1,300))
		print ("data to be transmitted: "+s)
		s=enc_dec("e",str(shared_key),s)
		print ("data transmitted after encryption: "+s)
		sock.send(s)
		time.sleep(2)

