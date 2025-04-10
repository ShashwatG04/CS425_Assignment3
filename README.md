# TCP Three-Way Handshake (Client) – Raw Socket Implementation

This project demonstrates how a TCP three-way handshake can be manually implemented using raw sockets in C++. It simulates the client-side logic of initiating a TCP connection without relying on the operating system's built-in TCP stack.

---

## Objective

The goal is to:

- Create a raw TCP socket.
- Manually construct IP and TCP headers.
- Send a SYN packet to the server.
- Wait for a SYN-ACK from the server.
- Respond with a final ACK to complete the handshake.

This exercise helps in understanding how TCP headers and checksums work under the hood.

---

## Files Included

- `client.cpp` – Raw socket client performing a manual TCP handshake.
- `server.cpp` – Provided server that replies with SYN-ACK and completes the handshake.
- `Makefile` – Used to build the client and server.
- `README.md` – This documentation file.

---

## Compilation Steps

1. Ensure all source files (`client.cpp`, `server.cpp`, `Makefile`) are in the same folder.
2. Run:
   ```bash
   make
   ```
   This will generate two executables: `client` and `server`.

---

## Running the Programs

1. **Start the Server:**

   ```bash
   sudo ./server
   ```

   The server will listen on `127.0.0.1:12345`.

2. **Start the Client (in another terminal):**

   ```bash
   sudo ./client
   ```

> Note: Raw sockets require root privileges, so both server and client should be run using `sudo`.

---

## Code Walkthrough

### 1. **Socket Setup**

- A raw socket is created:
  ```cpp
  socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  ```
- `IP_HDRINCL` is enabled to allow manual construction of the IP header:
  ```cpp
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
  ```

### 2. **SYN Packet – `send_syn()`**

- A buffer is prepared and split into IP and TCP header sections.
- IP header includes:
  - Version = 4
  - Protocol = TCP
  - Source and Destination IP = 127.0.0.1
- TCP header includes:
  - Source Port = 54321
  - Destination Port = 12345
  - Sequence Number = 200
  - SYN flag set to 1
- A TCP checksum is calculated using a pseudo-header.
- Packet is sent using `sendto()`.

### 3. **Waiting for SYN-ACK – `receive_syn_ack_and_send_ack()`**

- Enters a loop using `recvfrom()` to listen for packets.
- For each packet, checks:
  - Source port is 12345
  - Destination port is 54321
  - SYN and ACK flags are set
  - Sequence = 400, Ack = 201

### 4. **Final ACK**

- On receiving a valid SYN-ACK, constructs a final ACK packet:
  - Sequence Number = 600
  - Acknowledgment Number = 401
  - Only the ACK flag is set
- Calculates checksum and sends the ACK using `sendto()`
- Handshake is now complete.

### 5. **Cleanup**

- After sending the final ACK, socket is closed and program exits.

---

## Contributors

- Shashwat Gautam (221005)

---
