# Encrypted Client-Server Communication Framework

## 1. Project Overview

The Encrypted Client-Server Communication Framework is an educational networking project designed to demonstrate communication between clients and a server using Python. It aims to combine TCP socket communication, TLS encryption, user authentication, text messaging and file transfer with SHA-256-based file-integrity verification.

## 2. Objectives

- Establish client-server communication using TCP sockets.
- Protect communication using TLS.
- Implement user authentication.
- Support text messaging and file transfer.
- Verify file integrity using SHA-256 hashes.
- Evaluate functionality and performance through testing and packet analysis.

## 3. Technologies Used

- Python
- TCP sockets
- TLS/SSL
- JSON
- SHA-256
- Wireshark
- OpenSSL

_Retain only technologies used in the final implementation._

## 4. Project Structure

```text
encrypted-client-server/
├── client.py
├── server.py
├── certs/
│   ├── server.crt
│   └── server.key
├── files/
├── tests/
└── README.md
```

_Update this structure to match the actual project files._

## 5. Prerequisites

- Python 3 installed
- Required Python libraries, if any
- OpenSSL for certificate generation, if required
- Wireshark for packet-level analysis

## 6. Configuration

The demonstration configuration may use `127.0.0.1` as the host and `5000` as the port. Confirm the values in the final source code before running the project.

TLS certificate and key paths must also match the actual configuration.

## 7. Execution

1. Open a terminal in the project directory.
2. Start the server using the command appropriate to the project, for example:

   ```bash
   python server.py
   ```

3. Open another terminal and start the client:

   ```bash
   python client.py
   ```

4. Follow the client prompts to authenticate and use the implemented communication features.

_These commands are examples; adjust them if the project uses different filenames or arguments._

## 8. Testing

The framework should be evaluated using appropriate test cases for authentication, messaging, file transfer, file integrity, error handling and encrypted communication.

Record actual test outcomes and performance measurements rather than assuming that all tests pass.

## 9. Security Note

This project is intended for educational demonstration. Do not use demonstration credentials, unverified TLS certificates or other development-only security settings in a production environment.

## 10. Project Information

Project Title: Encrypted Client-Server Communication Framework

Language: Python

Purpose: Computer network project
