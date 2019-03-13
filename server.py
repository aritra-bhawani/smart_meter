import socket
from thread import *
import random
# import sqlite3
# from simplecrypt import encrypt, decrypt

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
        Device ID = 23
        key = 1234
    '''
    if d_id=='23' and key=='1234':
        return True

# def cypher_dec(text):
#     obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
#     print type(text), len(text)
#     d=obj.decrypt(text)
#     print d

def client_thread(conn,id):
    conn.send('connected\n')
    print('connected!\nVerification pending')
    (username,f) = ('',0)

    while True:
        if f==0: 
            if verify(conn):
                conn.send('verified\n')
                f=1
            else:
                conn.send('wrong\n') 
                # conn.close() 
                # break
        else:         
            data = conn.recv(1024).rstrip("\n\r")
            print ("data received:", data) 
            # print "decrypted data:", decrypt('10', data)
            # cypher_dec(data)
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


