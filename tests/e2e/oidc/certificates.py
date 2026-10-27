"""Throwaway certificates: a CA that only the app process trusts and a leaf
the browser is told to accept by the hash of its public key alone."""

from __future__ import annotations

import base64
import datetime
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VALIDITY = datetime.timedelta(days=1)
PRIVATE_FILE_MODE = 0o600


@dataclass(frozen=True)
class ThrowawayTls:
    ca_certificate: Path
    leaf_certificate: Path
    leaf_key: Path
    leaf_spki_sha256_base64: str


def issue_throwaway_tls(directory: Path, name: str, dns_names: list[str]) -> ThrowawayTls:
    """A CA and one leaf for ``dns_names`` with its own key, written under ``directory``."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} throwaway CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca = (
        _builder(ca_subject, ca_subject, ca_key.public_key(), now)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        _builder(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} throwaway leaf")]),
            ca_subject, leaf_key.public_key(), now,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    tls = ThrowawayTls(
        ca_certificate=directory / f"{name}-ca.pem",
        leaf_certificate=directory / f"{name}-leaf.pem",
        leaf_key=directory / f"{name}-leaf-key.pem",
        leaf_spki_sha256_base64=_spki_sha256_base64(leaf),
    )
    tls.ca_certificate.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    tls.leaf_certificate.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    tls.leaf_key.touch(mode=PRIVATE_FILE_MODE)
    tls.leaf_key.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return tls


def _builder(
    subject: x509.Name, issuer: x509.Name, public_key: ec.EllipticCurvePublicKey,
    now: datetime.datetime,
) -> x509.CertificateBuilder:
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + VALIDITY)
    )


def _spki_sha256_base64(certificate: x509.Certificate) -> str:
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()
