# Smart Meter
<i> This project is mainly focused to build a Smart Meter using the concepts of IoT, Cryptography and Block-chain technology.<i>

## Introduction:
> With the advancement of IoT based devices along with the increasing counts, the requirement of a smart metering system is inevitable. While connecting them to the cloud, we should also mind the security and transparency of the entire network. The secured aspects can be handled by different cryptographic methods. On the other hand, the transparency of every billing cycle can be maintained by Block-chain technology which in turn will be supported by the increasing number of IoT bases devices(Nodes).

The prototype of the meter (`node.py`) is running on Raspberry pi, which is supported by the Arduino to take the analog reading from the ACS712 current sensor and serially transmit the data to the Raspberry pi, due to the absence of analog GPIO pins on it.

<p align="center">
  <img src="https://i.postimg.cc/kXYypzRM/IMG-20190407-165734401.jpg" width="350" title="hover text">
<p>  
  
### Brief Description:
This project focuses mainly on four stands:
* Accurate Value Measurement : here ACS712 is interfaced with Arduino to measure the voltage in analog format and calculate the corresponding energy consumption and send the value to the Raspberry pi.
* IoT : a TCP connection is established between the server running (`server.py`) with the DB containing tables DEVICES and LEDGER. Once the connection is established, the Server asks for credentials. On successful validation of credentials from the DEVICES table, the connection is sustained else closed by the server.
* Cryptography : once the connection is successfully established, the server initiates a symmetric key (16 bits) exchanged with the node using Diffie-Hellman key exchange protocol (to protect against Man-in-the-middle attack). The encryption of the data takes place using the Advanced Encryption Standard (AES) and to validate the sender we are using the concept of Digital Signature (using RSA algorithm)
* Block-chain : This module is under development. In this process, the measured data will be stored in the form of a hash (which will depend on the hash of the previous reading). This will happen only when the validating node reaches a certain consensus measured by Byzantine Fault Tolerance. Keeping in mind, the limitations in the storage size and computation power of the meters (as they will be running on an embedded system), we will be using the method of polling to reach consensus and server will be logging the data into the database rather than performing any like POW or POS.
