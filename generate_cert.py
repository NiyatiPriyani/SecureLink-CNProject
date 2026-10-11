
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_DIR = Path("certs")
CERT_DIR.mkdir(exist_ok=True)

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CN Project"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

now = datetime.now(timezone.utc)

certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=1))
    .not_valid_after(now + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
        ]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)

(CERT_DIR / "server.key").write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

(CERT_DIR / "server.crt").write_bytes(
    certificate.public_bytes(serialization.Encoding.PEM)
)

print("Certificate created successfully!")
print("Certificate: certs/server.crt")
print("Private key: certs/server.key")
