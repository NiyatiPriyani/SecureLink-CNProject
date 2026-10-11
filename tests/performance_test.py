
import json
import socket
import ssl
import struct
import time
import statistics

HOST = "127.0.0.1"
PORT = 5000
SAMPLES = 20


def send_json(sock, data):
    payload = json.dumps(data).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_exactly(sock, size):
    chunks = []
    remaining = size

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def receive_json(sock):
    header = receive_exactly(sock, 4)
    size = struct.unpack("!I", header)[0]
    payload = receive_exactly(sock, size)
    return json.loads(payload.decode("utf-8"))


def main():
    context = ssl.create_default_context(cafile="certs/server.crt")
    latencies_ms = []

    with socket.create_connection((HOST, PORT)) as raw_socket:
        with context.wrap_socket(
            raw_socket,
            server_hostname="localhost",
        ) as secure_socket:

            send_json(secure_socket, {
                "type": "LOGIN",
                "username": "user1",
                "password": "1234",
            })

            response = receive_json(secure_socket)

            if response.get("type") != "OK":
                print("Login failed:", response)
                return

            for i in range(SAMPLES):
                message = f"Performance test message {i + 1}"

                start = time.perf_counter()

                send_json(secure_socket, {
                    "type": "MESSAGE",
                    "message": message,
                })

                response = receive_json(secure_socket)
                elapsed_ms = (time.perf_counter() - start) * 1000

                if response.get("type") != "OK":
                    print("Request failed:", response)
                    return

                latencies_ms.append(elapsed_ms)

            send_json(secure_socket, {"type": "LOGOUT"})
            receive_json(secure_socket)

    print("\n=== Performance Test Results ===")
    print("Successful message exchanges:", len(latencies_ms))
    print(f"Average round-trip latency: {statistics.mean(latencies_ms):.3f} ms")
    print(f"Median round-trip latency:  {statistics.median(latencies_ms):.3f} ms")
    print(f"Minimum latency:            {min(latencies_ms):.3f} ms")
    print(f"Maximum latency:            {max(latencies_ms):.3f} ms")


if __name__ == "__main__":
    main()
