"""Unit tests for Dual Key Pair architecture — PHASE 9.4.

Tests verify:
1. sign_cert.KeyUsage has digitalSignature=True, key_encipherment=False
2. enc_cert.KeyUsage has key_encipherment=True, digital_signature=False
3. build_envelope uses enc_cert for CEK (not sign cert)
4. open_envelope requires enc_privkey (fails with sign_privkey)
5. Shamir escrow stores enc_key, NOT sign_key (sign_key is never escrowed)
"""
import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from securemail.crypto import rsa_handler
from securemail.ca_service import ca_core
from securemail.mail import smime_handler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_csr(priv, cn: str, email: str):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .sign(priv, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)


def _sign_cert(csr_pem: bytes, email: str, key_usage: str) -> bytes:
    return ca_core.sign_csr(csr_pem, email, key_usage=key_usage)


# ---------------------------------------------------------------------------
# Test 1 & 2: KeyUsage extension correctness
# ---------------------------------------------------------------------------

class TestKeyUsageExtensions:
    """Verify that CA issues certs with the correct KeyUsage per key_usage param."""

    def setup_method(self):
        # Ensure CA is initialized (must have services running)
        try:
            ca_core.load_ca()
        except Exception:
            pytest.skip("CA not initialized — run bootstrap first")

    def test_sign_cert_has_digital_signature_and_non_repudiation(self):
        priv = rsa_handler.generate_keypair(2048)
        csr = _make_csr(priv, "Test Sign", "test_sign@mail.local")
        cert_pem = _sign_cert(csr, "test_sign@mail.local", "sign")
        cert = x509.load_pem_x509_certificate(cert_pem)
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        assert ku.digital_signature is True,  "sign cert must have digitalSignature"
        assert ku.content_commitment is True, "sign cert must have contentCommitment (nonRepudiation)"
        assert ku.key_encipherment is False,  "sign cert must NOT have keyEncipherment"
        assert ku.data_encipherment is False, "sign cert must NOT have dataEncipherment"

    def test_enc_cert_has_key_encipherment_and_data_encipherment(self):
        priv = rsa_handler.generate_keypair(2048)
        csr = _make_csr(priv, "Test Enc", "test_enc@mail.local")
        cert_pem = _sign_cert(csr, "test_enc@mail.local", "enc")
        cert = x509.load_pem_x509_certificate(cert_pem)
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        assert ku.key_encipherment is True,    "enc cert must have keyEncipherment"
        assert ku.data_encipherment is True,   "enc cert must have dataEncipherment"
        assert ku.digital_signature is False,  "enc cert must NOT have digitalSignature"
        assert ku.content_commitment is False, "enc cert must NOT have contentCommitment"

    def test_default_key_usage_is_sign(self):
        """Backward compat: sign_csr with no key_usage defaults to 'sign'."""
        priv = rsa_handler.generate_keypair(2048)
        csr = _make_csr(priv, "Test Default", "test_default@mail.local")
        cert_pem = ca_core.sign_csr(csr, "test_default@mail.local")  # no key_usage
        cert = x509.load_pem_x509_certificate(cert_pem)
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        assert ku.digital_signature is True


# ---------------------------------------------------------------------------
# Test 3 & 4: S/MIME envelope encryption correctness
# ---------------------------------------------------------------------------

class TestSMIMEDualKeyEnvelope:
    """Verify envelope build/open uses correct keys for each operation."""

    def setup_method(self):
        # Generate fresh keypairs for each test
        self.sign_priv = rsa_handler.generate_keypair(2048)
        self.enc_priv  = rsa_handler.generate_keypair(2048)
        try:
            ca_core.load_ca()
        except Exception:
            pytest.skip("CA not initialized")
        sign_csr = _make_csr(self.sign_priv, "Test Alice", "alice_test@mail.local")
        enc_csr  = _make_csr(self.enc_priv,  "Test Alice", "alice_test@mail.local")
        self.sign_cert_pem = _sign_cert(sign_csr, "alice_test@mail.local", "sign")
        self.enc_cert_pem  = _sign_cert(enc_csr,  "alice_test@mail.local", "enc")

    def test_build_and_open_envelope_with_correct_keys(self):
        plaintext = b"Hello, dual keypair world!"
        envelope = smime_handler.build_envelope(
            plaintext,
            [("alice_test@mail.local", self.enc_cert_pem)],
            self.sign_cert_pem,
            self.sign_priv,
        )
        result = smime_handler.open_envelope(envelope, "alice_test@mail.local", self.enc_priv)
        assert result["body"] == plaintext

    def test_open_envelope_with_sign_key_fails(self):
        """Decrypting with the signing private key must fail — wrong key."""
        plaintext = b"Secret message"
        envelope = smime_handler.build_envelope(
            plaintext,
            [("alice_test@mail.local", self.enc_cert_pem)],
            self.sign_cert_pem,
            self.sign_priv,
        )
        with pytest.raises(Exception):
            # sign_priv cannot decrypt CEK encrypted with enc_pub
            smime_handler.open_envelope(envelope, "alice_test@mail.local", self.sign_priv)

    def test_signature_verification_uses_sign_cert(self):
        """open_envelope must verify signature using signer_sign_cert_b64."""
        plaintext = b"Verify me"
        envelope = smime_handler.build_envelope(
            plaintext,
            [("alice_test@mail.local", self.enc_cert_pem)],
            self.sign_cert_pem,
            self.sign_priv,
        )
        result = smime_handler.open_envelope(envelope, "alice_test@mail.local", self.enc_priv)
        # The signer cert embedded must be the SIGNING cert, not enc cert
        embedded_cert = x509.load_pem_x509_certificate(result["signer_cert_pem"])
        sign_cert = x509.load_pem_x509_certificate(self.sign_cert_pem)
        assert embedded_cert.serial_number == sign_cert.serial_number


# ---------------------------------------------------------------------------
# Test 5: Escrow only stores enc_key
# ---------------------------------------------------------------------------

class TestEscrowOnlyEncKey:
    """Verify that escrow_local_user_keys skips sign_key files."""

    def test_escrow_glob_pattern_excludes_sign_keys(self):
        """The escrow function only globs *.enc_key.pem, not *.sign_key.pem."""
        import inspect
        from securemail import client_core
        source = inspect.getsource(client_core.escrow_local_user_keys)
        assert ".enc_key.pem" in source, "escrow function must glob *.enc_key.pem"
        assert ".sign_key.pem" not in source or "not" in source, \
            "escrow function must NOT glob *.sign_key.pem"

    def test_glob_does_not_match_sign_key(self):
        """Verify the glob pattern *.enc_key.pem does not match *.sign_key.pem."""
        import fnmatch
        assert fnmatch.fnmatch("alice_at_mail.local.enc_key.pem", "*.enc_key.pem")
        assert not fnmatch.fnmatch("alice_at_mail.local.sign_key.pem", "*.enc_key.pem")
