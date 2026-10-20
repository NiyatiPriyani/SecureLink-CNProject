
from pathlib import Path
import hashlib
import json
import socket
import ssl
import struct

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
CERT_FILE = BASE_DIR / "certs" / "server.crt"

app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

# Flask and the TCP/TLS server must use different ports.
TCP_HOST = "127.0.0.1"
TCP_PORT = 5001

MAX_MESSAGE_SIZE = 1024 * 1024
MAX_FILE_SIZE = 50 * 1024 * 1024
CHUNK_SIZE = 32 * 1024


# =========================
# TCP/TLS COMMUNICATION
# =========================

def receive_exactly(sock, size):
    """Receive exactly the requested number of bytes."""
    if size < 0:
        raise ValueError("Invalid byte count.")

    chunks = []
    remaining = size

    while remaining:
        data = sock.recv(min(4096, remaining))

        if not data:
            raise ConnectionError("Connection closed during transfer.")

        chunks.append(data)
        remaining -= len(data)

    return b"".join(chunks)


def send_json(sock, data):
    """Send a JSON message with a four-byte length prefix."""
    payload = json.dumps(data).encode("utf-8")

    if not payload or len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid JSON message size.")

    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_json(sock):
    """Receive one length-prefixed JSON message."""
    header = receive_exactly(sock, 4)
    size = struct.unpack("!I", header)[0]

    if size == 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid response size.")

    payload = receive_exactly(sock, size)
    response = json.loads(payload.decode("utf-8"))

    if not isinstance(response, dict):
        raise ValueError("Invalid server response.")

    return response


def connect_and_login(username, password):
    """Create a verified TLS connection and authenticate."""
    if not CERT_FILE.is_file():
        raise FileNotFoundError(
            f"TLS certificate not found: {CERT_FILE}"
        )

    context = ssl.create_default_context(cafile=str(CERT_FILE))

    raw_socket = socket.create_connection(
        (TCP_HOST, TCP_PORT),
        timeout=30,
    )

    try:
        secure_socket = context.wrap_socket(
            raw_socket,
            server_hostname="localhost",
        )
        secure_socket.settimeout(120)

        send_json(secure_socket, {
            "type": "LOGIN",
            "username": username,
            "password": password,
        })

        response = receive_json(secure_socket)

        if response.get("type") != "OK":
            secure_socket.close()
            raise PermissionError(
                response.get("message", "Login failed.")
            )

        return secure_socket

    except Exception:
        raw_socket.close()
        raise


# =========================
# RESUMABLE FILE UPLOAD
# =========================

def upload_to_tcp_server(file, filename, username, password):
    """Send the browser-uploaded file through the existing TLS protocol."""
    digest = hashlib.sha256()
    chunk_hashes = []
    file_size = 0

    # First pass: calculate the whole-file hash and chunk hashes.
    while True:
        data = file.stream.read(CHUNK_SIZE)

        if not data:
            break

        file_size += len(data)

        if file_size > MAX_FILE_SIZE:
            raise ValueError("File exceeds the 50 MB upload limit.")

        digest.update(data)
        chunk_hashes.append(hashlib.sha256(data).hexdigest())

    file_hash = digest.hexdigest()
    file.stream.seek(0)

    with connect_and_login(username, password) as sock:
        # Tell the server about the file.
        send_json(sock, {
            "type": "UPLOAD_START",
            "filename": filename,
            "file_size": file_size,
            "sha256": file_hash,
            "chunk_size": CHUNK_SIZE,
            "chunk_hashes": chunk_hashes,
        })

        response = receive_json(sock)

        if response.get("type") != "UPLOAD_READY":
            raise RuntimeError(
                response.get("message", "Server rejected the upload.")
            )

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
            raise RuntimeError("Invalid upload response from server.")

        # Send only chunks the server does not already have.
        for index in missing:
            file.stream.seek(index * CHUNK_SIZE)
            data = file.stream.read(CHUNK_SIZE)

            if hashlib.sha256(data).hexdigest() != chunk_hashes[index]:
                raise RuntimeError("File changed during upload.")

            send_json(sock, {
                "type": "FILE_CHUNK",
                "upload_id": upload_id,
                "index": index,
                "chunk_size": len(data),
            })

            sock.sendall(data)

            response = receive_json(sock)

            if (
                response.get("type") != "CHUNK_OK"
                or response.get("index") != index
            ):
                raise RuntimeError(
                    response.get("message", f"Chunk {index} failed.")
                )

        # Ask the server to assemble and verify the completed file.
        send_json(sock, {
            "type": "UPLOAD_FINISH",
            "upload_id": upload_id,
        })

        response = receive_json(sock)

        if response.get("type") != "OK":
            raise RuntimeError(
                response.get("message", "Final file verification failed.")
            )

        server_hash = response.get("sha256")

        if server_hash != file_hash:
            raise RuntimeError("Server and client SHA-256 hashes differ.")

        return {
            "status": "success",
            "filename": filename,
            "size_bytes": file_size,
            "sha256": file_hash,
            "server_sha256": server_hash,
            "message": response.get(
                "message",
                "File uploaded and verified successfully.",
            ),
        }


# =========================
# FLASK ROUTES
# =========================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({
        "status": "running",
        "message": "SecureLink Flask app is running.",
    })


@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file was provided."}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "Please select a file."}), 400

    # Prevent a submitted path from becoming a destination path.
    filename = file.filename.replace("\\", "/").split("/")[-1]

    if (
        not filename
        or filename in {".", ".."}
        or any(ord(char) < 32 for char in filename)
    ):
        return jsonify({"error": "Invalid filename."}), 400

    # The existing TCP/TLS server requires authentication.
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Enter your TCP server username and password."
        }), 400

    try:
        result = upload_to_tcp_server(
            file,
            filename,
            username,
            password,
        )
        return jsonify(result)

    except PermissionError as error:
        return jsonify({"error": str(error)}), 401

    except (ConnectionError, socket.timeout, TimeoutError) as error:
        return jsonify({
            "error": f"Could not complete the transfer: {error}"
        }), 502

    except FileNotFoundError as error:
        return jsonify({"error": str(error)}), 500

    except (ssl.SSLError, OSError) as error:
        return jsonify({
            "error": f"TLS/network error: {error}"
        }), 502

    except (ValueError, json.JSONDecodeError) as error:
        return jsonify({
            "error": f"Invalid communication data: {error}"
        }), 502

    except RuntimeError as error:
        return jsonify({"error": str(error)}), 502


@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "File exceeds the 50 MB upload limit."
    }), 413


if __name__ == "__main__":
    print("Project directory:", BASE_DIR)
    print("Template exists:", (TEMPLATE_DIR / "index.html").is_file())
    print(f"TCP/TLS server: {TCP_HOST}:{TCP_PORT}")
    app.run(debug=True, port=5000)
