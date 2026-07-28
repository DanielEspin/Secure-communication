#!/usr/bin/env python3
"""
make_cert.py - Generates server.crt and server.key without needing openssl.

Run once before starting main.py:
    python make_cert.py

Produces a self-signed cert valid for localhost and 127.0.0.1, with a proper
Subject Alternative Name. Python's ssl module requires SAN (it has ignored the
old Common Name field since 3.7), so a cert without one fails verification even
though it looks correct.
"""

import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTFILE, KEYFILE = "server.crt", "server.key"
DAYS_VALID = 365


def main():
    if os.path.exists(CERTFILE) or os.path.exists(KEYFILE):
        answer = input(f"{CERTFILE}/{KEYFILE} already exist. Overwrite? [y/N] ")
        if answer.strip().lower() != "y":
            print("Cancelled.")
            return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)                      # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))   # clock-skew slack
        .not_valid_after(now + datetime.timedelta(days=DAYS_VALID))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(KEYFILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(CERTFILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Wrote {CERTFILE} and {KEYFILE}, valid {DAYS_VALID} days.")
    print(f"Keep {KEYFILE} on the server only. Give clients a copy of {CERTFILE}.")


if __name__ == "__main__":
    main()
