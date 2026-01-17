# Smart Meter
<i>A distributed smart metering system integrating IoT, cryptography, and federated blockchain consensus.</i>

## Introduction:
> With the advancement of IoT-based devices along with the increasing counts, the requirement of a smart metering system is inevitable. While connecting them to the cloud, we should also mind the security and transparency of the entire network. The secured aspects can be handled by different cryptographic methods. On the other hand, the transparency of every billing cycle can be maintained by Blockchain technology which in turn will be supported by the increasing number of IoT-bases devices(Nodes).

The system is implemented as a distributed pseudonymous network with three main components: Certificate Authority (CA), Utility nodes, and Base Meter nodes. The CA manages authentication and maintains a database of all network participants. Utility nodes store the detailed ledger, while Base Meter nodes collect energy consumption data from sensors and store ledger checkpoints for future verification.

<p align="center">
  <img src="https://i.postimg.cc/kXYypzRM/IMG-20190407-165734401.jpg" width="350">
</p>

### Brief Description:
This project focuses mainly on four aspects:
* IoT : A distributed network using TCP connections between CA, Utility, and Base Meter nodes. Authentication is handled through the CA.
* Cryptography : Secure communication using Diffie-Hellman key exchange for symmetric key establishment, AES encryption for data transmission, and RSA digital signatures for authentication and integrity.
* Blockchain : Implemented through Federated Byzantine Agreement (FBA) consensus mechanism using quorum-based validation. Energy readings are validated by peer nodes before being recorded, ensuring data integrity and preventing tampering. The system uses hashing to create an immutable chain of readings.
* Accurate Value Measurement : ACS712 current sensor interfaced with Arduino measures voltage in analog format, calculates energy consumption, and transmits data to Base Meter nodes (Legacy).

## Current Implementation Status

The project has reached an advanced stage with the initial network setup completed. The consensus protocol is based on Federated Byzantine Agreement (FBA), allowing nodes to reach agreement on transaction validity without requiring global consensus, making it suitable for distributed IoT networks.

### Privacy and Compliance Features
The network maintains user pseudonymity by using cryptographic identifiers and avoiding direct personal data linkage in transactions. The system is designed with GDPR-awareness in mind by avoiding the storage of direct personal identifiers or consumption data on-chain. Personal data is managed off-chain by the CA and consumption data by the Utility with an pseudonymous id, allowing modification or erasure without compromising blockchain integrity.
 This is achieved through ledger validation mechanisms that enable selective data removal while maintaining the integrity of the overall blockchain.

### Data Storage Architecture
To accommodate computationally limited IoT devices:
- **Utility Nodes** maintain the complete ledger details for full transaction history and auditing.
- **Quorum Slice Nodes**(Base Meter nodes) store data using a Merkle tree approach, where only hash values of transaction blocks are kept locally, significantly reducing storage requirements while allowing efficient validation of the chain's integrity.

## Architecture

### Components:
- **Certificate Authority (CA)**: Central authority managing authentication, database operations, and network coordination.
- **Utility Nodes**: Handle billing calculations, quorum management, and data validation.
- **Base Meter Nodes**: IoT devices that collect energy readings from Arduino sensors and participate in the consensus network.

### Technologies Used:
- **Cryptography**: PyCryptoDome (AES, RSA, Diffie-Hellman)
- **Networking**: Python sockets for TCP communication
- **Database**: SQLite for storing user data, meter readings, and network state
- **Visualization**: NetworkX and Matplotlib for network topology visualization
- **Containerization**: Docker and Docker Compose for deployment
- **Hardware**: Arduino with ACS712 current sensor for energy measurement

## Setup and Running

### Prerequisites:
- Docker and Docker Compose
- Python 3.11+

### Running the System:
```bash
# Build and start the services
docker-compose up --scale utility=15 --scale base_meter=20

# Or for development
docker-compose up --scale utility=3 --scale base_meter=3
```

### Services:
- CA: Runs on port 5005
- Utility: Multiple instances for load distribution
- Base Meter: Multiple instances simulating IoT devices

### GUI Access:
The system includes a web-based dashboard for monitoring and authentication. Access the GUI through the provided HTML interface in the `GUI/` directory.

### Database:
The CA maintains a SQLite database (`certifying_authority_DB.db`) containing:
- Consumer information
- Meter registrations
- Quorum mappings
- Validation records

### Visualization:
Run `node_map.py` to generate network topology graphs showing node connections and validation status.

[![Screenshot-2026-01-01-at-3-42-20-AM.png](https://i.postimg.cc/B67QSqfj/Screenshot-2026-01-01-at-3-42-20-AM.png)](https://postimg.cc/7G7yXr64)

