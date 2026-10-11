
import hashlib
import json
import os
import socket
import ssl
import struct
import threading
from pathlib import Path

HOST = "127.0.0.1"
PORT = 5000

USERS = {
    "user1": "1234",
    "user2": "5678",
    "shraddha": "python123",
}

MAX_MESSAGE_SIZE = 1024 * 1024
MAX_FILE_SIZE = 50 * 1024 * 1024
FILES_DIR = Path("files")
FILES_DIR.mkdir(exist_ok=True)


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
        raise ConnectionError("Incomplete JSON message.")

    return json.loads(payload.decode("utf-8"))


def receive_file(sock, request, username):
    filename = request.get("filename")
    file_size = request.get("file_size")
    expected_hash = request.get("sha256")

    if not isinstance(filename, str) or not filename:
        send_json(sock, {"type": "ERROR", "message": "Invalid filename."})
        return

    # Only accept a plain filename, not a path supplied by the client.
    if Path(filename).name != filename or filename in {".", ".."}:
        send_json(sock, {"type": "ERROR", "message": "Invalid filename."})
        return

    if type(file_size) is not int or not 0 <= file_size <= MAX_FILE_SIZE:
        send_json(sock, {
            "type": "ERROR",
            "message": "File size must be between 0 and 50 MB.",
        })
        return

    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in expected_hash)
    ):
        send_json(sock, {"type": "ERROR", "message": "Invalid SHA-256 hash."})
        return

    destination = FILES_DIR / f"received_{filename}"
    temporary = FILES_DIR / f".upload_{threading.get_ident()}.tmp"
    digest = hashlib.sha256()
    remaining = file_size

    try:
        with temporary.open("wb") as output:
            while remaining > 0:
                chunk = sock.recv(min(4096, remaining))

                if not chunk:
                    raise ConnectionError("Connection closed during file transfer.")

                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)

        actual_hash = digest.hexdigest()
        hash_matches = actual_hash.lower() == expected_hash.lower()

        if not hash_matches:
            temporary.unlink(missing_ok=True)
            send_json(sock, {
                "type": "ERROR",
                "message": "SHA-256 mismatch. File rejected.",
                "sha256": actual_hash,
            })
            print(f"[HASH MISMATCH] {filename} from {username}")
            return

        os.replace(temporary, destination)

        print(f"[FILE RECEIVED] {filename} from {username}")
        print(f"[SHA-256 VERIFIED] {actual_hash}")

        send_json(sock, {
            "type": "OK",
            "message": "File received and SHA-256 verified.",
            "filename": filename,
            "sha256": actual_hash,
        })

    finally:
        temporary.unlink(missing_ok=True)


def handle_client(secure_socket, address):
    print(f"[CONNECTED] {address}")
    authenticated_user = None

    try:
        while True:
            request = receive_json(secure_socket)

            if request is None:
                break

            if not isinstance(request, dict):
                send_json(secure_socket, {
                    "type": "ERROR",
                    "message": "Request must be a JSON object.",
                })
                continue

            request_type = request.get("type")

            if request_type == "LOGIN":
                username = request.get("username")
                password = request.get("password")

                if (
                    isinstance(username, str)
                    and isinstance(password, str)
                    and username in USERS
                    and USERS[username] == password
                ):
                    authenticated_user = username
                    print(f"[LOGIN SUCCESS] {username}")

                    send_json(secure_socket, {
                        "type": "OK",
                        "message": f"Welcome, {username}!",
                    })
                else:
                    send_json(secure_socket, {
                        "type": "ERROR",
                        "message": "Invalid username or password.",
                    })

            elif request_type == "MESSAGE":
                if authenticated_user is None:
                    send_json(secure_socket, {
                        "type": "ERROR",
                        "message": "Please log in first.",
                    })
                    continue

                message = request.get("message")

                if not isinstance(message, str) or not message.strip():
                    send_json(secure_socket, {
                        "type": "ERROR",
                        "message": "Message cannot be empty.",
                    })
                    continue

                if len(message) > 5000:
                    send_json(secure_socket, {
                        "type": "ERROR",
                        "message": "Message exceeds 5000 characters.",
                    })
                    continue

                print(f"[MESSAGE] {authenticated_user}: {message}")

                send_json(secure_socket, {
                    "type": "OK",
                    "message": f"Server received your message: {message}",
                })

            elif request_type == "FILE":
                if authenticated_user is None:
                    send_json(secure_socket, {
                        "type": "ERROR",
                        "message": "Please log in first.",
                    })
                    continue

                receive_file(secure_socket, request, authenticated_user)

            elif request_type == "LOGOUT":
                send_json(secure_socket, {
                    "type": "OK",
                    "message": "Logged out successfully.",
                })
                break

            else:
                send_json(secure_socket, {
                    "type": "ERROR",
                    "message": "Unknown request type.",
                })

    except (ConnectionError, ssl.SSLError, OSError) as error:
        print(f"[CONNECTION ERROR] {address}: {error}")

    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"[INVALID DATA] {address}: {error}")

    finally:
        secure_socket.close()
        print(f"[DISCONNECTED] {address}")


def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile="certs/server.crt",
        keyfile="certs/server.key",
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    print(f"TLS server running on {HOST}:{PORT}")
    print("Waiting for secure connections...")

    try:
        while True:
            client_socket, address = server.accept()

            try:
                secure_socket = context.wrap_socket(
                    client_socket,
                    server_side=True,
                )
            except (ConnectionError, ssl.SSLError, OSError) as error:
                print(f"[TLS HANDSHAKE FAILED] {address}: {error}")
                client_socket.close()
                continue

            threading.Thread(
                target=handle_client,
                args=(secure_socket, address),
                daemon=True,
            ).start()

    except KeyboardInterrupt:
        print("\nTLS server shutting down.")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()
