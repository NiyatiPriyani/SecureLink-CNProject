
import hashlib
import json
import socket
import ssl
import struct
from pathlib import Path

HOST = "127.0.0.1"
PORT = 5000
MAX_MESSAGE_SIZE = 1024 * 1024
MAX_FILE_SIZE = 50 * 1024 * 1024


def receive_exactly(sock, size):
    chunks = []
    remaining = size

    while remaining > 0:
        chunk = sock.recv(min(4096, remaining))

        if not chunk:
            if not chunks:
                return None
            raise ConnectionError("Connection closed during data transfer.")

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def send_json(sock, data):
    payload = json.dumps(data).encode("utf-8")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("Message is too large.")

    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_json(sock):
    header = receive_exactly(sock, 4)

    if header is None:
        return None

    size = struct.unpack("!I", header)[0]

    if size == 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid message size.")

    payload = receive_exactly(sock, size)

    if payload is None:
        raise ConnectionError("Incomplete JSON response.")

    return json.loads(payload.decode("utf-8"))


def send_file(sock, file_path):
    path = Path(file_path).expanduser()

    if not path.is_file():
        print("File not found:", path)
        return

    file_size = path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        print("File is too large. Maximum size is 50 MB.")
        return

    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            digest.update(chunk)

    file_hash = digest.hexdigest()

    send_json(sock, {
        "type": "FILE",
        "filename": path.name,
        "file_size": file_size,
        "sha256": file_hash,
    })

    # Send the raw file bytes immediately after the framed JSON metadata.
    with path.open("rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            sock.sendall(chunk)

    response = receive_json(sock)
    print("Server response:", response)

    if response and response.get("type") == "OK":
        print("Original SHA-256:", file_hash)
        print("Server SHA-256:  ", response.get("sha256"))


def start_client():
    context = ssl.create_default_context(cafile="certs/server.crt")

    try:
        with socket.create_connection((HOST, PORT)) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname="localhost",
            ) as secure_socket:

                print("TLS connected:", secure_socket.version())

                username = input("Username: ").strip()
                password = input("Password: ")

                send_json(secure_socket, {
                    "type": "LOGIN",
                    "username": username,
                    "password": password,
                })

                response = receive_json(secure_socket)
                print("Server response:", response)

                if response is None or response.get("type") != "OK":
                    print("Login failed. Closing connection.")
                    return

                print("\nCommands:")
                print("  Type any text to send a message.")
                print("  /file <path> to send a file.")
                print("  /logout to disconnect.")
                print(r'Example: /file files\sample.txt')

                while True:
                    command = input("You: ").strip()

                    if not command:
                        continue

                    if command == "/logout":
                        send_json(secure_socket, {"type": "LOGOUT"})
                        print("Server response:", receive_json(secure_socket))
                        break

                    if command.startswith("/file "):
                        file_path = command[len("/file "):].strip().strip('"')
                        send_file(secure_socket, file_path)
                        continue

                    send_json(secure_socket, {
                        "type": "MESSAGE",
                        "message": command,
                    })

                    print("Server response:", receive_json(secure_socket))

    except ConnectionRefusedError:
        print("Could not connect. Is the server running?")

    except ssl.SSLCertVerificationError as error:
        print("Certificate verification failed:", error)

    except (ConnectionError, ssl.SSLError, OSError, ValueError, json.JSONDecodeError) as error:
        print("Connection or protocol error:", error)


if __name__ == "__main__":
    start_client()
