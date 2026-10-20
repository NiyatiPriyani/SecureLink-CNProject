
import hashlib
import time
import json
import socket
import ssl
import struct
from pathlib import Path


# =========================
# CLIENT CONFIGURATION
# =========================

HOST = "127.0.0.1"
PORT = 5001

MAX_MESSAGE_SIZE = 1024 * 1024       # 1 MB
MAX_FILE_SIZE = 50 * 1024 * 1024     # 50 MB
CHUNK_SIZE = 32 * 1024               # 32 KB


# =========================
# NETWORK COMMUNICATION
# =========================

def receive_exactly(sock, size):
    """Receive exactly size bytes over TCP."""
    if size < 0:
        raise ValueError("Invalid byte count.")

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
    """Send JSON with a 4-byte length prefix."""
    payload = json.dumps(data).encode("utf-8")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("Message is too large.")

    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_json(sock):
    """Receive one length-prefixed JSON message."""
    header = receive_exactly(sock, 4)

    if header is None:
        return None

    size = struct.unpack("!I", header)[0]

    if size == 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid JSON message size.")

    payload = receive_exactly(sock, size)

    if payload is None:
        raise ConnectionError("Incomplete JSON response.")

    return json.loads(payload.decode("utf-8"))


# =========================
# ORIGINAL FILE TRANSFER
# =========================

def send_file(sock, file_path):
    """Send a complete file using the original /file protocol."""
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
            data = file.read(4096)

            if not data:
                break

            digest.update(data)

    file_hash = digest.hexdigest()

    send_json(sock, {
        "type": "FILE",
        "filename": path.name,
        "file_size": file_size,
        "sha256": file_hash,
    })

    with path.open("rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sock.sendall(data)

    response = receive_json(sock)
    print("Server response:", response)

    if response and response.get("type") == "OK":
        print("Original SHA-256:", file_hash)
        print("Server SHA-256:  ", response.get("sha256"))


# =========================
# RESUMABLE CHUNKED UPLOAD
# =========================

def send_resumable_file(sock, file_path):
    """
    Upload a file in chunks, sending only the chunks the server is missing.
    The server verifies chunk hashes and the final complete-file hash.
    """
    path = Path(file_path).expanduser()

    if not path.is_file():
        print("File not found:", path)
        return

    file_size = path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        print("File is too large. Maximum size is 50 MB.")
        return

    whole_digest = hashlib.sha256()
    chunk_hashes = []

    # Calculate the complete-file hash and individual chunk hashes.
    with path.open("rb") as file:
        while True:
            data = file.read(CHUNK_SIZE)

            if not data:
                break

            whole_digest.update(data)
            chunk_hashes.append(hashlib.sha256(data).hexdigest())

    file_hash = whole_digest.hexdigest()

    # Tell the server about the file and its chunks.
    send_json(sock, {
        "type": "UPLOAD_START",
        "filename": path.name,
        "file_size": file_size,
        "sha256": file_hash,
        "chunk_size": CHUNK_SIZE,
        "chunk_hashes": chunk_hashes,
    })

    response = receive_json(sock)

    if not response or response.get("type") != "UPLOAD_READY":
        print("Could not start or resume upload:", response)
        return

    upload_id = response.get("upload_id")
    missing = response.get("missing")

    if (
        not isinstance(upload_id, str)
        or not isinstance(missing, list)
        or any(
            type(index) is not int
            or index < 0
            or index >= len(chunk_hashes)
            for index in missing
        )
        or len(set(missing)) != len(missing)
    ):
        print("Invalid upload response from server.")
        return

    total_chunks = len(chunk_hashes)
    already_uploaded = total_chunks - len(missing)

    print(
        f"Server already has {already_uploaded}/{total_chunks} "
        "verified chunks."
    )
    print(f"Sending {len(missing)} missing chunks...")

    # Send only missing chunks, one at a time.
    with path.open("rb") as file:
        for count, index in enumerate(missing, start=1):
            file.seek(index * CHUNK_SIZE)
            data = file.read(CHUNK_SIZE)

            expected_hash = chunk_hashes[index]

            if hashlib.sha256(data).hexdigest() != expected_hash:
                print("File changed during upload. Please try again.")
                return

            send_json(sock, {
                "type": "FILE_CHUNK",
                "upload_id": upload_id,
                "index": index,
                "chunk_size": len(data),
            })

            sock.sendall(data)

            response = receive_json(sock)

            if (
                not response
                or response.get("type") != "CHUNK_OK"
                or response.get("index") != index
            ):
                print(f"Chunk {index} was not accepted:", response)
                return

            
            print(f"Uploaded {count}/{len(missing)} missing chunks.")

            time.sleep(0.3)


    # Ask the server to assemble the file and verify its complete hash.
    send_json(sock, {
        "type": "UPLOAD_FINISH",
        "upload_id": upload_id,
    })

    response = receive_json(sock)
    print("Server response:", response)

    if response and response.get("type") == "OK":
        print("Original SHA-256:", file_hash)
        print("Server SHA-256:  ", response.get("sha256"))
        print("File upload completed and verified.")


# =========================
# START CLIENT
# =========================

def start_client():
    context = ssl.create_default_context(
        cafile="certs/server.crt"
    )

    try:
        with socket.create_connection((HOST, PORT)) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname="localhost",
            ) as secure_socket:

                print("=" * 45)
                print(" Secure Client-Server Communication")
                print("=" * 45)
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

                if not response or response.get("type") != "OK":
                    print("Login failed. Disconnecting.")
                    return

                print("\nLogin successful!")
                print("\nAvailable commands:")
                print("  Type a message to send a text message.")
                print('  /file <path>   - Send a file normally.')
                print('  /resume <path> - Upload or resume a file.')
                print("  /logout        - Disconnect from the server.")
                print()

                while True:
                    command = input("You: ").strip()

                    if not command:
                        continue

                    if command == "/logout":
                        send_json(secure_socket, {
                            "type": "LOGOUT",
                        })

                        print("Server response:", receive_json(secure_socket))
                        break

                    if command.startswith("/resume "):
                        file_path = (
                            command[len("/resume "):]
                            .strip()
                            .strip('"')
                        )

                        send_resumable_file(secure_socket, file_path)
                        continue

                    if command.startswith("/file "):
                        file_path = (
                            command[len("/file "):]
                            .strip()
                            .strip('"')
                        )

                        send_file(secure_socket, file_path)
                        continue

                    send_json(secure_socket, {
                        "type": "MESSAGE",
                        "message": command,
                    })

                    print("Server response:", receive_json(secure_socket))

    except ConnectionRefusedError:
        print("Could not connect. Make sure server.py is running.")

    except ssl.SSLError as error:
        print("TLS error:", error)

    except (ConnectionError, OSError) as error:
        print("Connection error:", error)

    except (ValueError, json.JSONDecodeError) as error:
        print("Communication error:", error)

    except KeyboardInterrupt:
        print("\nClient stopped.")


if __name__ == "__main__":
    start_client()
