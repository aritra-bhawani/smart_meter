import socket
from thread import *
import random
import time
# import sqlite3
from Crypto.Cipher import AES # same key for encrypting and decrypting 128bit encryption
import base64
import os

host = ''
port = 10000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connections = {}

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

try:
	s.bind((host,port))
	print ("server started")
	ip = get_ip()
	print ("IP :", ip)
	print ("port :",port)
	print ("listening...")
except socket.error as e:
	print(str(e))

s.listen(10)
print ("listening on port:",s.getsockname()[1])

def verify(conn):
    # to be checked form the Data Base1
    (d_id,key)=('','')
    while d_id=='':
        conn.send("Device ID:")
        d_id=conn.recv(1024).rstrip("\n\r")
        print ("ID:", d_id)
    while key=='':
        conn.send("Access key:")
        key=conn.recv(1024).rstrip("\n\r") 
        print ("Key:", key)
    '''
        Device ID = 23 or 24
        key = 1234 or 12345
    '''
    if (d_id=='23' and key=='1234') or (d_id=='24' and key=='12345'):
        return True

# applying Diffie-Hellman key sharing protocol
def DHK_exc_s(key,conn):
    sharedPrime=9999999900000001
    sharedBase=102124190
    conn.send(str(sharedPrime))
    time.sleep(.1)
    conn.send(str(sharedBase))
    A=int(conn.recv(1024).rstrip("\n\r")) #3. receiving A
    B=(sharedBase ** key) % sharedPrime #4. calculating B
    conn.send(str(B)) #5. send the value of B
    shared_key = (A**key) % sharedPrime
    return ([True,shared_key])

# encryption and decryption using AES
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

def client_thread(conn,id):
    shared_key=''
    conn.send('connected\n')
    print('connected!\nVerification pending')
    (username,f,e,serverSecret) = ('',0,0,random.randint(5,20))
    while True:
        if f==0: 
            if verify(conn):
                conn.send('verified\n')
                f=1
            else:
                conn.send('wrong\n')
        elif e==0:
            r=DHK_exc_s(serverSecret,conn)
            if r[0]:
                print('Key Exchange Successful\nShared Key:')
                shared_key=str(r[1])
                print(shared_key)
                conn.send('Key Exchange Successful')
                e=1
            else:
                print ('Key Exchnage Failed')
                conn.send('Key Exchnage Failed')
        else:
            data=conn.recv(1024).rstrip("\n\r")
            print ("data received: "+str(data))
            data=enc_dec("d",shared_key,data)
            print ("data retrieved after decrypting: "+data)
            # print (data)
            if not data:
                connections.pop(id)
                conn.close()
                break                      
    conn.close()


while True:
    conn , addr = s.accept()
    print('connected to:' +addr[0] +":"+str(addr[1]))

    id = random.randint(1,9999999999)
    start_new_thread(client_thread,(conn,id))
    
    connections.update({id:conn})
    print(connections)
