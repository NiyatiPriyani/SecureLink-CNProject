
import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
import threading
from pathlib import Path


# =========================
# SERVER CONFIGURATION
# =========================

HOST = "127.0.0.1"
PORT = 5001

USERS = {
    "user1": "1234",
    "user2": "5678",
    "shraddha": "python123",
}

MAX_MESSAGE_SIZE = 1024 * 1024       # 1 MB
MAX_FILE_SIZE = 50 * 1024 * 1024     # 50 MB
CHUNK_SIZE = 32 * 1024               # 32 KB

FILES_DIR = Path("files")
FILES_DIR.mkdir(exist_ok=True)

CHUNK_STORE = FILES_DIR / ".chunk_store"
CHUNK_STORE.mkdir(exist_ok=True)

# Protects operations on upload manifests and chunk files within this process.
UPLOAD_LOCK = threading.RLock()


# =========================
# NETWORK COMMUNICATION
# =========================

def receive_exactly(sock, size):
    """Receive exactly size bytes, even if TCP delivers them in pieces."""
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
    """Send JSON with a 4-byte network-order length prefix."""
    payload = json.dumps(data).encode("utf-8")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("Message is too large.")

    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


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
        raise ConnectionError("Incomplete JSON message.")

    return json.loads(payload.decode("utf-8"))


def send_error(sock, message):
    send_json(sock, {
        "type": "ERROR",
        "message": message,
    })


# =========================
# VALIDATION HELPERS
# =========================

def valid_sha256(value):
    """Return True if value is a 64-character hexadecimal SHA-256 hash."""
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def valid_filename(filename):
    """Reject empty names and path traversal attempts."""
    if not isinstance(filename, str):
        return False

    if not filename or filename in {".", ".."}:
        return False

    if len(filename) > 200:
        return False

    if "/" in filename or "\\" in filename:
        return False

    if Path(filename).name != filename:
        return False

    if any(ord(char) < 32 for char in filename):
        return False

    return True


def upload_directory(upload_id):
    """Only accept server-generated SHA-256-shaped upload IDs."""
    if not valid_sha256(upload_id):
        raise ValueError("Invalid upload ID.")

    return CHUNK_STORE / upload_id.lower()


def read_manifest(folder):
    """Read and validate an upload manifest."""
    manifest_path = folder / "manifest.json"

    with manifest_path.open("r", encoding="utf-8") as file:
        manifest = json.load(file)

    if not isinstance(manifest, dict):
        raise ValueError("Invalid upload manifest.")

    filename = manifest.get("filename")
    file_size = manifest.get("file_size")
    file_hash = manifest.get("sha256")
    chunk_size = manifest.get("chunk_size")
    chunk_hashes = manifest.get("chunk_hashes")
    username = manifest.get("username")

    if not valid_filename(filename):
        raise ValueError("Invalid filename in upload manifest.")

    if type(file_size) is not int or not 0 <= file_size <= MAX_FILE_SIZE:
        raise ValueError("Invalid file size in upload manifest.")

    if not valid_sha256(file_hash):
        raise ValueError("Invalid file hash in upload manifest.")

    if chunk_size != CHUNK_SIZE:
        raise ValueError("Invalid chunk size in upload manifest.")

    if not isinstance(username, str):
        raise ValueError("Invalid upload owner.")

    if not isinstance(chunk_hashes, list):
        raise ValueError("Invalid chunk hash list.")

    expected_count = (
        (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    )

    if len(chunk_hashes) != expected_count:
        raise ValueError("Invalid number of chunk hashes.")

    if not all(valid_sha256(item) for item in chunk_hashes):
        raise ValueError("Invalid chunk hash.")

    return manifest


def expected_chunk_length(manifest, index):
    """Calculate the expected byte length of a chunk."""
    total_chunks = len(manifest["chunk_hashes"])

    if type(index) is not int or not 0 <= index < total_chunks:
        raise ValueError("Invalid chunk index.")

    if index < total_chunks - 1:
        return CHUNK_SIZE

    return manifest["file_size"] - index * CHUNK_SIZE


def find_missing_chunks(folder, manifest):
    """
    Return chunks that are absent or fail their stored SHA-256 check.
    Existing valid chunks can be reused after a reconnect.
    """
    missing = []

    for index, expected_hash in enumerate(manifest["chunk_hashes"]):
        chunk_path = folder / f"chunk_{index}.bin"
        expected_length = expected_chunk_length(manifest, index)

        if not chunk_path.is_file():
            missing.append(index)
            continue

        try:
            if chunk_path.stat().st_size != expected_length:
                chunk_path.unlink(missing_ok=True)
                missing.append(index)
                continue

            digest = hashlib.sha256()

            with chunk_path.open("rb") as file:
                while True:
                    data = file.read(4096)
                    if not data:
                        break
                    digest.update(data)

            if digest.hexdigest() != expected_hash.lower():
                chunk_path.unlink(missing_ok=True)
                missing.append(index)

        except OSError:
            missing.append(index)

    return missing


# =========================
# ORIGINAL FILE TRANSFER
# =========================

def receive_file(sock, request, username):
    """Receive a complete file using the original /file protocol."""
    filename = request.get("filename")
    file_size = request.get("file_size")
    expected_hash = request.get("sha256")

    if not valid_filename(filename):
        send_error(sock, "Invalid filename.")
        return

    if type(file_size) is not int or not 0 <= file_size <= MAX_FILE_SIZE:
        send_error(sock, "Invalid file size. Maximum size is 50 MB.")
        return

    if not valid_sha256(expected_hash):
        send_error(sock, "Invalid SHA-256 hash.")
        return

    destination = FILES_DIR / f"received_{filename}"
    temporary = FILES_DIR / (
        f".upload_{threading.get_ident()}.tmp"
    )

    digest = hashlib.sha256()
    remaining = file_size

    try:
        with temporary.open("wb") as output:
            while remaining > 0:
                data = sock.recv(min(4096, remaining))

                if not data:
                    raise ConnectionError(
                        "Connection closed during file transfer."
                    )

                output.write(data)
                digest.update(data)
                remaining -= len(data)

        actual_hash = digest.hexdigest()

        if actual_hash.lower() != expected_hash.lower():
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


# =========================
# RESUMABLE FILE TRANSFER
# =========================

def handle_upload_start(sock, request, username):
    """
    Start or resume an upload.

    The server creates a stable upload ID from the authenticated username,
    filename, file size, and complete-file hash. Valid chunks already on
    disk are retained across client disconnections and server restarts.
    """
    filename = request.get("filename")
    file_size = request.get("file_size")
    file_hash = request.get("sha256")
    chunk_size = request.get("chunk_size")
    chunk_hashes = request.get("chunk_hashes")

    if not valid_filename(filename):
        send_error(sock, "Invalid filename.")
        return

    if type(file_size) is not int or not 0 <= file_size <= MAX_FILE_SIZE:
        send_error(sock, "Invalid file size. Maximum size is 50 MB.")
        return

    if not valid_sha256(file_hash):
        send_error(sock, "Invalid complete-file SHA-256 hash.")
        return

    if chunk_size != CHUNK_SIZE:
        send_error(
            sock,
            f"Chunk size must be {CHUNK_SIZE} bytes."
        )
        return

    if not isinstance(chunk_hashes, list):
        send_error(sock, "Invalid chunk hash list.")
        return

    expected_count = (
        (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    )

    if len(chunk_hashes) != expected_count:
        send_error(sock, "Incorrect number of chunk hashes.")
        return

    if not all(valid_sha256(item) for item in chunk_hashes):
        send_error(sock, "One or more chunk hashes are invalid.")
        return

    normalized_hash = file_hash.lower()
    normalized_chunk_hashes = [
        item.lower() for item in chunk_hashes
    ]

    upload_identity = json.dumps(
        [
            username,
            filename,
            file_size,
            normalized_hash,
        ],
        separators=(",", ":"),
    ).encode("utf-8")

    upload_id = hashlib.sha256(upload_identity).hexdigest()
    folder = upload_directory(upload_id)

    manifest = {
        "username": username,
        "filename": filename,
        "file_size": file_size,
        "sha256": normalized_hash,
        "chunk_size": CHUNK_SIZE,
        "chunk_hashes": normalized_chunk_hashes,
    }

    with UPLOAD_LOCK:
        folder.mkdir(parents=True, exist_ok=True)
        manifest_path = folder / "manifest.json"

        if manifest_path.exists():
            try:
                existing = read_manifest(folder)
            except (OSError, ValueError, json.JSONDecodeError):
                send_error(sock, "Existing upload metadata is invalid.")
                return

            if existing != manifest:
                send_error(
                    sock,
                    "Upload metadata does not match the existing upload."
                )
                return
        else:
            temporary_manifest = folder / "manifest.tmp"

            with temporary_manifest.open(
                "w", encoding="utf-8"
            ) as file:
                json.dump(manifest, file)

            os.replace(temporary_manifest, manifest_path)

        missing = find_missing_chunks(folder, manifest)

    total_chunks = len(normalized_chunk_hashes)
    received_chunks = total_chunks - len(missing)

    print(
        f"[UPLOAD START] {filename} from {username}: "
        f"{received_chunks}/{total_chunks} chunks already verified"
    )

    send_json(sock, {
        "type": "UPLOAD_READY",
        "upload_id": upload_id,
        "missing": missing,
        "total_chunks": total_chunks,
    })


def handle_file_chunk(sock, request, username):
    """
    Receive one chunk and verify it before saving it.

    If chunk metadata is invalid before the raw bytes are read, close the
    connection rather than leaving unread bytes to corrupt the protocol.
    """
    upload_id = request.get("upload_id")
    index = request.get("index")
    declared_size = request.get("chunk_size")

    if not valid_sha256(upload_id):
        raise ConnectionError("Invalid upload ID in chunk request.")

    folder = upload_directory(upload_id)

    with UPLOAD_LOCK:
        try:
            manifest = read_manifest(folder)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise ConnectionError(
                "Upload manifest is missing or invalid."
            ) from error

        if manifest["username"] != username:
            raise ConnectionError("Upload owner mismatch.")

        try:
            expected_size = expected_chunk_length(manifest, index)
        except ValueError as error:
            raise ConnectionError("Invalid chunk index.") from error

        if type(declared_size) is not int or declared_size != expected_size:
            raise ConnectionError("Invalid chunk size.")

    # Read the declared, validated number of raw bytes.
    data = receive_exactly(sock, expected_size)

    if data is None:
        raise ConnectionError("Connection closed before chunk data arrived.")

    actual_hash = hashlib.sha256(data).hexdigest()
    expected_hash = manifest["chunk_hashes"][index].lower()

    if actual_hash != expected_hash:
        send_json(sock, {
            "type": "ERROR",
            "message": f"SHA-256 mismatch for chunk {index}.",
            "index": index,
        })

        print(f"[CHUNK REJECTED] {upload_id}, chunk {index}")
        return

    with UPLOAD_LOCK:
        # Re-read metadata in case the upload changed while bytes arrived.
        current_manifest = read_manifest(folder)

        if current_manifest != manifest:
            raise ConnectionError("Upload metadata changed unexpectedly.")

        destination = folder / f"chunk_{index}.bin"
        temporary = folder / f"chunk_{index}.tmp"

        with temporary.open("wb") as file:
            file.write(data)

        os.replace(temporary, destination)

    send_json(sock, {
        "type": "CHUNK_OK",
        "index": index,
        "sha256": actual_hash,
    })

    print(
        f"[CHUNK VERIFIED] {manifest['filename']}: "
        f"{index + 1}/{len(manifest['chunk_hashes'])}"
    )


def handle_upload_finish(sock, request, username):
    """Assemble verified chunks and verify the complete file."""
    upload_id = request.get("upload_id")

    if not valid_sha256(upload_id):
        send_error(sock, "Invalid upload ID.")
        return

    folder = upload_directory(upload_id)

    with UPLOAD_LOCK:
        try:
            manifest = read_manifest(folder)
        except (OSError, ValueError, json.JSONDecodeError):
            send_error(sock, "Upload metadata is missing or invalid.")
            return

        if manifest["username"] != username:
            send_error(sock, "You do not own this upload.")
            return

        missing = find_missing_chunks(folder, manifest)

        if missing:
            send_json(sock, {
                "type": "ERROR",
                "message": "Upload is incomplete.",
                "missing": missing,
            })
            return

        filename = manifest["filename"]
        file_size = manifest["file_size"]
        expected_hash = manifest["sha256"].lower()

        temporary = FILES_DIR / f".assembled_{upload_id}.tmp"
        destination = FILES_DIR / f"received_{filename}"

        digest = hashlib.sha256()
        assembled_size = 0

        try:
            with temporary.open("wb") as output:
                for index in range(len(manifest["chunk_hashes"])):
                    chunk_path = folder / f"chunk_{index}.bin"
                    expected_length = expected_chunk_length(
                        manifest, index
                    )
                    expected_chunk_hash = (
                        manifest["chunk_hashes"][index].lower()
                    )

                    # Verify again during assembly. This also detects
                    # changes to stored chunk files before finalization.
                    chunk_digest = hashlib.sha256()
                    chunk_length = 0

                    with chunk_path.open("rb") as chunk_file:
                        while True:
                            data = chunk_file.read(4096)

                            if not data:
                                break

                            chunk_digest.update(data)
                            digest.update(data)
                            output.write(data)

                            chunk_length += len(data)
                            assembled_size += len(data)

                    if chunk_length != expected_length:
                        send_error(
                            sock,
                            f"Stored chunk {index} has an invalid size."
                        )
                        return

                    if chunk_digest.hexdigest() != expected_chunk_hash:
                        send_error(
                            sock,
                            f"Stored chunk {index} failed verification."
                        )
                        return

            actual_hash = digest.hexdigest()

            if assembled_size != file_size:
                send_error(sock, "Final file size does not match.")
                return

            if actual_hash != expected_hash:
                send_json(sock, {
                    "type": "ERROR",
                    "message": "Complete-file SHA-256 mismatch.",
                    "sha256": actual_hash,
                })

                print(f"[FINAL HASH MISMATCH] {filename}")
                return

            os.replace(temporary, destination)
            shutil.rmtree(folder)

            print(f"[RESUMABLE UPLOAD COMPLETE] {filename} from {username}")
            print(f"[SHA-256 VERIFIED] {actual_hash}")

            send_json(sock, {
                "type": "OK",
                "message": "Resumable upload completed and SHA-256 verified.",
                "filename": filename,
                "sha256": actual_hash,
            })

        finally:
            temporary.unlink(missing_ok=True)


# =========================
# CLIENT REQUEST HANDLER
# =========================

def handle_client(secure_socket, address):
    print(f"[CONNECTED] {address}")

    authenticated_user = None

    try:
        while True:
            request = receive_json(secure_socket)

            if request is None:
                break

            if not isinstance(request, dict):
                send_error(secure_socket, "Request must be a JSON object.")
                continue

            request_type = request.get("type")

            # LOGIN
            if request_type == "LOGIN":
                username = request.get("username")
                password = request.get("password")

                if (
                    isinstance(username, str)
                    and isinstance(password, str)
                    and USERS.get(username) == password
                ):
                    authenticated_user = username

                    print(f"[LOGIN SUCCESS] {username}")

                    send_json(secure_socket, {
                        "type": "OK",
                        "message": "Login successful.",
                        "username": username,
                    })
                else:
                    print(f"[LOGIN FAILED] {address}")

                    send_error(
                        secure_socket,
                        "Invalid username or password."
                    )

            # MESSAGE
            elif request_type == "MESSAGE":
                if authenticated_user is None:
                    send_error(
                        secure_socket,
                        "Please log in before sending messages."
                    )
                    continue

                message = request.get("message")

                if not isinstance(message, str) or not message.strip():
                    send_error(secure_socket, "Message cannot be empty.")
                    continue

                if len(message) > 5000:
                    send_error(
                        secure_socket,
                        "Message exceeds the 5000-character limit."
                    )
                    continue

                print(f"[MESSAGE] {authenticated_user}: {message}")

                send_json(secure_socket, {
                    "type": "OK",
                    "message": "Message received securely.",
                })

            # ORIGINAL NON-RESUMABLE FILE TRANSFER
            elif request_type == "FILE":
                if authenticated_user is None:
                    send_error(
                        secure_socket,
                        "Please log in before uploading files."
                    )
                    continue

                receive_file(
                    secure_socket,
                    request,
                    authenticated_user,
                )

            # START OR RESUME AN UPLOAD
            elif request_type == "UPLOAD_START":
                if authenticated_user is None:
                    send_error(
                        secure_socket,
                        "Please log in before uploading files."
                    )
                    continue

                handle_upload_start(
                    secure_socket,
                    request,
                    authenticated_user,
                )

            # RECEIVE ONE CHUNK
            elif request_type == "FILE_CHUNK":
                if authenticated_user is None:
                    # A conforming client sends no raw chunk before login.
                    send_error(
                        secure_socket,
                        "Please log in before uploading files."
                    )
                    continue

                handle_file_chunk(
                    secure_socket,
                    request,
                    authenticated_user,
                )

            # ASSEMBLE AND VERIFY UPLOAD
            elif request_type == "UPLOAD_FINISH":
                if authenticated_user is None:
                    send_error(
                        secure_socket,
                        "Please log in before finishing an upload."
                    )
                    continue

                handle_upload_finish(
                    secure_socket,
                    request,
                    authenticated_user,
                )

            # LOGOUT
            elif request_type == "LOGOUT":
                send_json(secure_socket, {
                    "type": "OK",
                    "message": "Logged out successfully.",
                })

                break

            else:
                send_error(secure_socket, "Unknown request type.")

    except (ConnectionError, ssl.SSLError, OSError) as error:
        print(f"[CONNECTION ERROR] {address}: {error}")

    except (
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as error:
        print(f"[INVALID REQUEST] {address}: {error}")

        try:
            send_error(secure_socket, "Invalid request data.")
        except (OSError, ssl.SSLError):
            pass

    finally:
        try:
            secure_socket.close()
        except OSError:
            pass

        print(f"[DISCONNECTED] {address}")


# =========================
# START TLS SERVER
# =========================

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.load_cert_chain(
        certfile="certs/server.crt",
        keyfile="certs/server.key",
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen()

        print("=" * 50)
        print(" Secure Client-Server Communication Server")
        print("=" * 50)
        print(f"Listening on {HOST}:{PORT}")
        print("TLS encryption enabled.")
        print(f"Maximum file size: {MAX_FILE_SIZE // (1024 * 1024)} MB")
        print(f"Resumable upload chunk size: {CHUNK_SIZE // 1024} KB")
        print("Waiting for clients...\n")

        while True:
            raw_socket, address = server.accept()

            try:
                secure_socket = context.wrap_socket(
                    raw_socket,
                    server_side=True,
                )

            except (ssl.SSLError, OSError) as error:
                print(f"[TLS HANDSHAKE FAILED] {address}: {error}")
                raw_socket.close()
                continue

            thread = threading.Thread(
                target=handle_client,
                args=(secure_socket, address),
                daemon=True,
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n[SERVER STOPPED] Shutting down server.")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()
