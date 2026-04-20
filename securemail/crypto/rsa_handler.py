"""RSA-2048: keygen, sign (PSS), verify, OAEP encrypt/decrypt, PEM load/save."""
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_keypair(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def serialize_private_pem(priv: rsa.RSAPrivateKey, passphrase: bytes | None = None) -> bytes:
    if passphrase:
        algo = serialization.BestAvailableEncryption(passphrase)
    else:
        algo = serialization.NoEncryption()
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algo,
    )


def load_private_pem(pem: bytes, passphrase: bytes | None = None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=passphrase)


def serialize_public_pem(pub: rsa.RSAPublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_pem(pem: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem)


def oaep_encrypt(pub: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    return pub.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def oaep_decrypt(priv: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return priv.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def pss_sign(priv: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return priv.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def pss_verify(pub: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
    try:
        pub.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
