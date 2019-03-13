import socket
import sys
# import serial
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# host = input('enter IP of server') #192.168.43.212
# port = int(input('enter Port to connect')) #10000
host = '192.168.43.212'
port = 10000
sock.connect((host,port))

f=0
# arduino = serial.Serial("/dev/ttyACM0")
# arduino.baudrate=9600

while True:
	response=sock.recv(1024).rstrip("\n")
	# print response
	if f==0 and response=='connected':
		print(sock.recv(1024).rstrip("\n"))
		d_id=str(input())
		sock.send(d_id)

		print(sock.recv(1024).rstrip("\n"))
		key=str(input())
		sock.send(key)

		response_new=sock.recv(1024).rstrip("\n")
		# print response_new
		if response_new=='verified':
			print "Successfully Verified"
			f=1
		else:
			print "Check the credentials and try again!"
			break
	while True:
		# data = arduino.readline()
		# pieces =data.split("\r\n")

		# print pieces[0]
		# time.sleep(5)

		s=str(time.time())+" => 200"
		print ("transmitted data",s)
		sock.send(s)
		time.sleep(2)

