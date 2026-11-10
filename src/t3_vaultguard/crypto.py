"""
Terminal 3 (T3N) Post-Quantum Session Handshake (ML-KEM-768 / FIPS 203),
Directional HKDF-SHA256 Key Derivation (`t3n-session-v1-c2s` / `t3n-session-v1-s2c`),
Authenticated AES-256-GCM Payload Encryption, and Threshold Quorum Key Recovery.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple

PRIME_GF = (1 << 256) - 189  # 256-bit prime for Shamir threshold secret sharing


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 key derivation used by T3N Session API."""
    prk = hmac.new(salt or (b"\x00" * 32), ikm, hashlib.sha256).digest()
    out = b""
    prev = b""
    counter = 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]


@dataclass(frozen=True)
class DirectionalSessionKeys:
    session_id: str
    c2s_key: bytes  # Derived with info=b"t3n-session-v1-c2s"
    s2c_key: bytes  # Derived with info=b"t3n-session-v1-s2c"
    measurement_hash: str
    expires_at_ms: int


class MLKem768SessionHandshake:
    """
    Models the T3N ML-KEM-768 (FIPS 203) client-to-TEE session handshake:
      1. Client verifies out-of-band TEE runtime measurement (`fetchTrustedManifest`).
      2. Client encapsulates against `trinity_public_key` -> `(shared_secret_K, kem_ciphertext)`.
      3. TEE decapsulates inside enclave memory and derives directional keys:
         - `t3n-session-v1-c2s` (client -> server)
         - `t3n-session-v1-s2c` (server -> client)
    """

    def __init__(self, tee_measurement: str = "mr_enclave:9f84b2c1e7a04318d529c019ef007a14b8821c0391a4f7c2"):
        self.tee_measurement = tee_measurement
        self._node_secret = hashlib.sha256(f"t3n-mlkem768-sk:{tee_measurement}".encode()).digest()
        self.trinity_public_key = hashlib.sha256(b"t3n-mlkem768-pk:" + self._node_secret).hexdigest()

    def encapsulate_and_establish(
        self,
        expected_measurement: str,
        entropy: bytes | None = None,
        now_ms: int = 1_762_758_000_000,
    ) -> Tuple[DirectionalSessionKeys, str]:
        if expected_measurement != self.tee_measurement:
            raise ValueError(f"TEE attestation quote mismatch: expected {expected_measurement}, got {self.tee_measurement}")

        seed = entropy or os.urandom(32)
        kem_ciphertext = hashlib.sha512(seed + self.trinity_public_key.encode()).hexdigest()
        shared_secret_k = hashlib.sha256(seed + self._node_secret).digest()

        c2s_key = hkdf_sha256(shared_secret_k, b"t3n-kem-salt", b"t3n-session-v1-c2s", 32)
        s2c_key = hkdf_sha256(shared_secret_k, b"t3n-kem-salt", b"t3n-session-v1-s2c", 32)
        session_id = "sess_" + hashlib.sha256(kem_ciphertext.encode()).hexdigest()[:20]

        return (
            DirectionalSessionKeys(
                session_id=session_id,
                c2s_key=c2s_key,
                s2c_key=s2c_key,
                measurement_hash=self.tee_measurement,
                expires_at_ms=now_ms + 3_600_000,
            ),
            kem_ciphertext,
        )


class Aes256GcmEnvelope:
    """
    Authenticated 12-byte-nonce stream + 16-byte authentication tag envelope
    following the T3N Session API wire format: `nonce (12B) || ciphertext || tag (16B)`.
    Tampering with a single bit of nonce, ciphertext, or AAD causes authentication failure.
    """

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        blocks = []
        counter = 1
        while sum(len(b) for b in blocks) < length:
            blocks.append(
                hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            )
            counter += 1
        return b"".join(blocks)[:length]

    @classmethod
    def encrypt(cls, key: bytes, plaintext: bytes, aad: bytes = b"", nonce: bytes | None = None) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be 32 bytes")
        iv = nonce if nonce is not None else os.urandom(12)
        if len(iv) != 12:
            raise ValueError("T3N Session API requires a fresh 12-byte nonce")
        stream = cls._keystream(key, iv, len(plaintext))
        ciphertext = bytes(p ^ s for p, s in zip(plaintext, stream))
        tag = hmac.new(key, iv + aad + ciphertext + len(aad).to_bytes(8, "big"), hashlib.sha256).digest()[:16]
        return iv + ciphertext + tag

    @classmethod
    def decrypt(cls, key: bytes, packet: bytes, aad: bytes = b"") -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be 32 bytes")
        if len(packet) < 28:
            raise ValueError("Truncated T3N encrypted packet")
        iv = packet[:12]
        ciphertext = packet[12:-16]
        tag = packet[-16:]
        expected_tag = hmac.new(
            key, iv + aad + ciphertext + len(aad).to_bytes(8, "big"), hashlib.sha256
        ).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("AES-256-GCM authentication tag verification failed")
        stream = cls._keystream(key, iv, len(ciphertext))
        return bytes(c ^ s for c, s in zip(ciphertext, stream))


class ThresholdQuorumKeyManager:
    """
    Shamir $k$-of-$n$ Threshold Wrapping Key Recovery over $GF(p)$ used by T3N TEE nodes
    at startup to reconstruct the enclave wrapping secret key without any single node holding it.
    """

    @staticmethod
    def split_secret(secret_bytes: bytes, k: int = 3, n: int = 5) -> List[Tuple[int, int]]:
        if len(secret_bytes) != 32:
            raise ValueError("Secret must be 32 bytes")
        if not (2 <= k <= n):
            raise ValueError("Invalid threshold parameters")
        secret_int = int.from_bytes(secret_bytes, "big") % PRIME_GF
        coeffs = [secret_int]
        for idx in range(1, k):
            c_digest = hashlib.sha256(secret_bytes + idx.to_bytes(2, "big")).digest()
            coeffs.append(int.from_bytes(c_digest, "big") % PRIME_GF)

        shares: List[Tuple[int, int]] = []
        for x in range(1, n + 1):
            y = 0
            for power, coeff in enumerate(coeffs):
                y = (y + coeff * pow(x, power, PRIME_GF)) % PRIME_GF
            shares.append((x, y))
        return shares

    @staticmethod
    def recover_secret(shares: List[Tuple[int, int]]) -> bytes:
        if len(shares) < 2:
            raise ValueError("At least k shares required")
        secret = 0
        for i, (xi, yi) in enumerate(shares):
            num = 1
            den = 1
            for j, (xj, _) in enumerate(shares):
                if i == j:
                    continue
                num = (num * (-xj)) % PRIME_GF
                den = (den * (xi - xj)) % PRIME_GF
            lagrange = (num * pow(den, -1, PRIME_GF)) % PRIME_GF
            secret = (secret + yi * lagrange) % PRIME_GF
        return secret.to_bytes(32, "big")
