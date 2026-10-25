from __future__ import annotations

import hmac
import logging
import struct
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..ua import MessageSecurityMode, SecurityPolicyType, UaError
from ..ua.uaerrors import SignatureError

if TYPE_CHECKING:
    from ..crypto.permission_rules import PermissionRuleset

from ..crypto import uacrypto

_logger = logging.getLogger(__name__)


class Signer(ABC):
    """
    Abstract base class for cryptographic signature algorithm
    """

    @abstractmethod
    def signature_size(self):
        pass

    @abstractmethod
    def signature(self, data):
        pass


class Verifier(ABC):
    """
    Abstract base class for cryptographic signature verification
    """

    @abstractmethod
    def signature_size(self):
        pass

    @abstractmethod
    def verify(self, data, signature):
        pass

    def reset(self):
        attrs = self.__dict__
        for k in attrs:
            attrs[k] = None


class Encryptor(ABC):
    """
    Abstract base class for encryption algorithm
    """

    @abstractmethod
    def plain_block_size(self):
        pass

    @abstractmethod
    def encrypted_block_size(self):
        pass

    @abstractmethod
    def encrypt(self, data):
        pass


class Decryptor(ABC):
    """
    Abstract base class for decryption algorithm
    """

    @abstractmethod
    def plain_block_size(self):
        pass

    @abstractmethod
    def encrypted_block_size(self):
        pass

    @abstractmethod
    def decrypt(self, data):
        pass

    def reset(self):
        attrs = self.__dict__
        for k in attrs:
            attrs[k] = None


class CryptographyNone:
    """
    Base class for symmetric/asymmetric cryptography
    """

    def __init__(self):
        pass

    def plain_block_size(self):
        """
        Size of plain text block for block cipher.
        """
        return 1

    def encrypted_block_size(self):
        """
        Size of encrypted text block for block cipher.
        """
        return 1

    def padding(self, size):
        """
        Create padding for a block of given size.
        plain_size = size + len(padding) + signature_size()
        plain_size = N * plain_block_size()
        """
        return b""

    def min_padding_size(self):
        return 0

    def signature_size(self):
        return 0

    def signature(self, data):
        return b""

    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data

    def vsignature_size(self):
        return 0

    def verify(self, data, signature):
        """
        Verify signature and raise exception if signature is invalid
        """

    def remove_padding(self, data):
        return data


class Cryptography(CryptographyNone):
    """
    Security policy: Sign or SignAndEncrypt
    """

    def __init__(self, mode=MessageSecurityMode.Sign):
        self.Signer = None
        self.Verifier = None
        self.Prev_Verifier = None
        self.Encryptor = None
        self.Decryptor = None
        self.Prev_Decryptor = None
        # we turn this flag on to fallback on previous key
        self._use_prev_key = False
        self.key_expiration = 0.0
        self.prev_key_expiration = 0.0
        if mode not in (MessageSecurityMode.Sign, MessageSecurityMode.SignAndEncrypt):
            raise ValueError(f"unknown security mode {mode}")
        self.is_encrypted = mode == MessageSecurityMode.SignAndEncrypt

    def plain_block_size(self):
        """
        Size of plain text block for block cipher.
        """
        if self.is_encrypted:
            return self.Encryptor.plain_block_size()
        return 1

    def encrypted_block_size(self):
        """
        Size of encrypted text block for block cipher.
        """
        if self.is_encrypted:
            return self.Encryptor.encrypted_block_size()
        return 1

    def padding(self, size):
        """
        Create padding for a block of given size.
        plain_size = size + len(padding) + signature_size()
        plain_size = N * plain_block_size()
        """
        if not self.is_encrypted:
            return b""
        block_size = self.Encryptor.plain_block_size()
        extrapad_size = 2 if self.Encryptor.encrypted_block_size() > 256 else 1
        rem = (size + self.signature_size() + extrapad_size) % block_size
        if rem != 0:
            rem = block_size - rem
        data = bytes(bytearray([rem % 256])) * (rem + 1)
        if self.Encryptor.encrypted_block_size() > 256:
            data += bytes(bytearray([rem >> 8]))
        return data

    def min_padding_size(self):
        if self.is_encrypted:
            return 1
        return 0

    def signature_size(self):
        return self.Signer.signature_size()

    def signature(self, data):
        return self.Signer.signature(data)

    def vsignature_size(self):
        return self.Verifier.signature_size()

    def verify(self, data, sig):
        if not self.use_prev_key:
            self.Verifier.verify(data, sig)
        else:
            _logger.debug("Message verification fallback: trying with previous secure channel key")
            self.Prev_Verifier.verify(data, sig)

    def encrypt(self, data):
        if self.is_encrypted:
            if not len(data) % self.Encryptor.plain_block_size() == 0:
                raise ValueError
            return self.Encryptor.encrypt(data)
        return data

    def decrypt(self, data):
        if self.is_encrypted:
            self.revoke_expired_key()
            if self.use_prev_key:
                return self.Prev_Decryptor.decrypt(data)
            return self.Decryptor.decrypt(data)
        return data

    def revoke_expired_key(self):
        """
        Remove expired keys as soon as possible
        """
        now = time.monotonic()
        if now > self.prev_key_expiration:
            if self.Prev_Decryptor and self.Prev_Verifier:
                self.Prev_Decryptor.reset()
                self.Prev_Decryptor = None
                self.Prev_Verifier.reset()
                self.Prev_Verifier = None
                _logger.debug("Expired secure_channel keys removed")

    @property
    def use_prev_key(self):
        if self._use_prev_key:
            if self.Prev_Decryptor and self.Prev_Verifier:
                return True
            raise SignatureError("signature does not match the data")
        return False

    @use_prev_key.setter
    def use_prev_key(self, value: bool):
        self._use_prev_key = value

    def remove_padding(self, data):
        decryptor = self.Decryptor if not self.use_prev_key else self.Prev_Decryptor
        if self.is_encrypted:
            if decryptor.encrypted_block_size() > 256:
                pad_size = struct.unpack("<h", data[-2:])[0] + 2
            else:
                pad_size = bytearray(data[-1:])[0] + 1
            return data[:-pad_size]
        return data


class SignerRsa(Signer):
    def __init__(self, host_privkey):
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8

    def signature_size(self):
        return self.key_size

    def signature(self, data):
        return uacrypto.sign_sha1(self.host_privkey, data)


class VerifierRsa(Verifier):
    def __init__(self, peer_cert):
        self.peer_cert = peer_cert
        self.key_size = self.peer_cert.public_key().key_size // 8

    def signature_size(self):
        return self.key_size

    def verify(self, data, signature):
        uacrypto.verify_sha1(self.peer_cert, data, signature)


class EncryptorRsa(Encryptor):
    def __init__(self, peer_cert, enc_fn, padding_size):
        self.peer_cert = peer_cert
        self.key_size = self.peer_cert.public_key().key_size // 8
        self.encryptor = enc_fn
        self.padding_size = padding_size

    def plain_block_size(self):
        return self.key_size - self.padding_size

    def encrypted_block_size(self):
        return self.key_size

    def encrypt(self, data):
        encrypted = b""
        block_size = self.plain_block_size()
        for i in range(0, len(data), block_size):
            encrypted += self.encryptor(self.peer_cert.public_key(), data[i : i + block_size])
        return encrypted


class DecryptorRsa(Decryptor):
    def __init__(self, host_privkey, dec_fn, padding_size):
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8
        self.decryptor = dec_fn
        self.padding_size = padding_size

    def plain_block_size(self):
        return self.key_size - self.padding_size

    def encrypted_block_size(self):
        return self.key_size

    def decrypt(self, data):
        decrypted = b""
        block_size = self.encrypted_block_size()
        for i in range(0, len(data), block_size):
            decrypted += self.decryptor(self.host_privkey, data[i : i + block_size])
        return decrypted


class SignerAesCbc(Signer):
    def __init__(self, key):
        self.key = key

    def signature_size(self):
        return uacrypto.sha1_size()

    def signature(self, data):
        return uacrypto.hmac_sha1(self.key, data)


class VerifierAesCbc(Verifier):
    def __init__(self, key):
        self.key = key

    def signature_size(self):
        return uacrypto.sha1_size()

    def verify(self, data, signature):
        expected = uacrypto.hmac_sha1(self.key, data)
        if not hmac.compare_digest(signature, expected):
            raise SignatureError("signature does not match the data")


class EncryptorAesCbc(Encryptor):
    def __init__(self, key, init_vec):
        self.cipher = uacrypto.cipher_aes_cbc(key, init_vec)

    def plain_block_size(self):
        return self.cipher.algorithm.block_size // 8

    def encrypted_block_size(self):
        return self.cipher.algorithm.block_size // 8

    def encrypt(self, data):
        return uacrypto.cipher_encrypt(self.cipher, data)


class DecryptorAesCbc(Decryptor):
    def __init__(self, key, init_vec):
        self.cipher = uacrypto.cipher_aes_cbc(key, init_vec)

    def plain_block_size(self):
        return self.cipher.algorithm.block_size // 8

    def encrypted_block_size(self):
        return self.cipher.algorithm.block_size // 8

    def decrypt(self, data):
        return uacrypto.cipher_decrypt(self.cipher, data)


class SignerSha256(Signer):
    def __init__(self, host_privkey):
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8

    def signature_size(self):
        return self.key_size

    def signature(self, data):
        return uacrypto.sign_sha256(self.host_privkey, data)


class VerifierSha256(Verifier):
    def __init__(self, peer_cert):
        self.peer_cert = peer_cert
        self.key_size = self.peer_cert.public_key().key_size // 8

    def signature_size(self):
        return self.key_size

    def verify(self, data, signature):
        uacrypto.verify_sha256(self.peer_cert, data, signature)


class SignerHMac256(Signer):
    def __init__(self, key):
        self.key = key

    def signature_size(self):
        return uacrypto.sha256_size()

    def signature(self, data):
        return uacrypto.hmac_sha256(self.key, data)


class VerifierHMac256(Verifier):
    def __init__(self, key):
        self.key = key

    def signature_size(self):
        return uacrypto.sha256_size()

    def verify(self, data, signature):
        expected = uacrypto.hmac_sha256(self.key, data)
        if not hmac.compare_digest(signature, expected):
            raise SignatureError("signature does not match the data")


class SignerPssSha256(Signer):
    def __init__(self, host_privkey):
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8

    def signature_size(self):
        return self.key_size

    def signature(self, data):
        return uacrypto.sign_pss_sha256(self.host_privkey, data)


class VerifierPssSha256(Verifier):
    def __init__(self, peer_cert):
        self.peer_cert = peer_cert
        self.key_size = self.peer_cert.public_key().key_size // 8

    def signature_size(self):
        return self.key_size

    def verify(self, data, signature):
        uacrypto.verify_pss_sha256(self.peer_cert, data, signature)


class SecurityPolicy(ABC):
    """
    Abstract base class for security policy
    """

    URI: str
    AsymmetricEncryptionURI: str
    AsymmetricSignatureURI: str
    secure_channel_nonce_length: int
    asymmetric_cryptography: CryptographyNone
    symmetric_cryptography: CryptographyNone
    Mode: MessageSecurityMode
    peer_certificate: bytes | None
    host_certificate: bytes | None
    permissions: PermissionRuleset | None
    host_certificate_chain: list[bytes]

    @abstractmethod
    def __init__(self, peer_cert, host_cert, host_privkey, mode, permission_ruleset=None, host_cert_chain=None):
        pass

    @staticmethod
    def encrypt_asymmetric(pubkey, data):
        raise UaError("The security policy has no asymmetric encryption")

    @staticmethod
    def sign_asymmetric(privkey, data):
        raise UaError("The security policy has no asymmetric signature")

    @abstractmethod
    def make_local_symmetric_key(self, secret, seed):
        pass

    @abstractmethod
    def make_remote_symmetric_key(self, secret, seed, lifetime):
        pass


class SecurityPolicyNone(SecurityPolicy):
    URI = "http://opcfoundation.org/UA/SecurityPolicy#None"
    AsymmetricEncryptionURI: str = ""
    AsymmetricSignatureURI: str = ""
    secure_channel_nonce_length: int = 0

    def __init__(
        self,
        peer_cert=None,
        host_cert=None,
        host_privkey=None,
        mode=MessageSecurityMode.None_,
        permission_ruleset=None,
        host_cert_chain=None,
    ):
        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        self.asymmetric_cryptography = CryptographyNone()
        self.symmetric_cryptography = CryptographyNone()
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    def make_local_symmetric_key(self, secret, seed):
        return None

    def make_remote_symmetric_key(self, secret, seed, lifetime):
        return None


class RsaSecurityPolicy(SecurityPolicy):
    signature_key_size: int
    symmetric_key_size: int
    deprecated: bool = False
    key_expiry_factor: float = 1.0
    asymmetric_padding_size: int
    asymmetric_signer: type[Signer]
    asymmetric_verifier: type[Verifier]
    symmetric_signer: type[Signer]
    symmetric_verifier: type[Verifier]
    encrypt_function: Callable[[Any, bytes], bytes]
    decrypt_function: Callable[[Any, bytes], bytes]
    p_hash: Callable[[bytes, bytes, tuple[int, ...]], tuple[bytes, ...]]

    def __init__(self, peer_cert, host_cert, host_privkey, mode, permission_ruleset=None, host_cert_chain=None):
        if self.deprecated:
            _logger.warning("DEPRECATED! Do not use %s anymore!", type(self).__name__)
        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        self.asymmetric_cryptography = Cryptography(MessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.Signer = self.asymmetric_signer(host_privkey)
        self.asymmetric_cryptography.Verifier = self.asymmetric_verifier(peer_cert)
        self.asymmetric_cryptography.Encryptor = EncryptorRsa(
            peer_cert, self.encrypt_function, self.asymmetric_padding_size
        )
        self.asymmetric_cryptography.Decryptor = DecryptorRsa(
            host_privkey, self.decrypt_function, self.asymmetric_padding_size
        )
        self.symmetric_cryptography = Cryptography(mode)
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    def _derive_keys(self, secret, seed):
        return self.p_hash(secret, seed, (self.signature_key_size, self.symmetric_key_size, 16))

    def make_local_symmetric_key(self, secret, seed):
        (sigkey, key, init_vec) = self._derive_keys(secret, seed)
        self.symmetric_cryptography.Signer = self.symmetric_signer(sigkey)
        self.symmetric_cryptography.Encryptor = EncryptorAesCbc(key, init_vec)

    def make_remote_symmetric_key(self, secret, seed, lifetime):
        (sigkey, key, init_vec) = self._derive_keys(secret, seed)
        if self.symmetric_cryptography.Verifier or self.symmetric_cryptography.Decryptor:
            self.symmetric_cryptography.Prev_Verifier = self.symmetric_cryptography.Verifier
            self.symmetric_cryptography.Prev_Decryptor = self.symmetric_cryptography.Decryptor
            self.symmetric_cryptography.prev_key_expiration = self.symmetric_cryptography.key_expiration

        self.symmetric_cryptography.key_expiration = time.monotonic() + (lifetime * 0.001 * self.key_expiry_factor)
        self.symmetric_cryptography.Verifier = self.symmetric_verifier(sigkey)
        self.symmetric_cryptography.Decryptor = DecryptorAesCbc(key, init_vec)


class SecurityPolicyAes128Sha256RsaOaep(RsaSecurityPolicy):
    """
    Security Aes128 Sha256 RsaOaep
    A suite of algorithms that uses Sha256 as Key-Wrap-algorithm
    and 128-Bit (16 bytes) for encryption algorithms.

    - SymmetricSignatureAlgorithm_HMAC-SHA2-256
      https://tools.ietf.org/html/rfc4634
    - SymmetricEncryptionAlgorithm_AES128-CBC
      http://www.w3.org/2001/04/xmlenc#aes128-cbc
    - AsymmetricSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA1
      http://www.w3.org/2001/04/xmlenc#rsa-oaep
    - KeyDerivationAlgorithm_P-SHA2-256
      http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256
    - CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - Aes128Sha256RsaOaep_Limits
        -> DerivedSignatureKeyLength: 256 bits
        -> MinAsymmetricKeyLength: 2048 bits
        -> MaxAsymmetricKeyLength: 4096 bits
        -> SecureChannelNonceLength: 32 bytes
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    AsymmetricSignatureURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    secure_channel_nonce_length = 32

    signature_key_size = 32
    symmetric_key_size = 16
    asymmetric_padding_size = 42
    asymmetric_signer = SignerSha256
    asymmetric_verifier = VerifierSha256
    symmetric_signer = SignerHMac256
    symmetric_verifier = VerifierHMac256
    encrypt_function = staticmethod(uacrypto.encrypt_rsa_oaep)
    decrypt_function = staticmethod(uacrypto.decrypt_rsa_oaep)
    p_hash = staticmethod(uacrypto.p_sha256)
    encrypt_asymmetric = staticmethod(uacrypto.encrypt_rsa_oaep)
    sign_asymmetric = staticmethod(uacrypto.sign_sha256)


class SecurityPolicyAes256Sha256RsaPss(RsaSecurityPolicy):
    """Security policy Aes256_Sha256_RsaPss implementation

    - SymmetricSignatureAlgorithm_HMAC-SHA2-256
      https://tools.ietf.org/html/rfc4634
    - SymmetricEncryptionAlgorithm_AES256-CBC
      http://www.w3.org/2001/04/xmlenc#aes256-cbc
    - AsymmetricSignatureAlgorithm_RSA-PSS-SHA2-256
      http://opcfoundation.org/UA/security/rsa-pss-sha2-256
    - AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA2-256
      http://opcfoundation.org/UA/security/rsa-oaep-sha2-256
    - KeyDerivationAlgorithm_P-SHA2-256
      http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256
    - CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - Aes256Sha256RsaPss_Limits
        -> DerivedSignatureKeyLength: 256 bits
        -> MinAsymmetricKeyLength: 2048 bits
        -> MaxAsymmetricKeyLength: 4096 bits
        -> SecureChannelNonceLength: 32 bytes
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
    AsymmetricEncryptionURI = "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256"
    AsymmetricSignatureURI = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256"
    secure_channel_nonce_length = 32

    signature_key_size = 32
    symmetric_key_size = 32
    asymmetric_padding_size = 66
    asymmetric_signer = SignerPssSha256
    asymmetric_verifier = VerifierPssSha256
    symmetric_signer = SignerHMac256
    symmetric_verifier = VerifierHMac256
    encrypt_function = staticmethod(uacrypto.encrypt_rsa_oaep_sha256)
    decrypt_function = staticmethod(uacrypto.decrypt_rsa_oaep_sha256)
    p_hash = staticmethod(uacrypto.p_sha256)
    encrypt_asymmetric = staticmethod(uacrypto.encrypt_rsa_oaep_sha256)
    sign_asymmetric = staticmethod(uacrypto.sign_pss_sha256)


class SecurityPolicyBasic128Rsa15(RsaSecurityPolicy):
    """
    DEPRECATED, do not use anymore!

    Security Basic 128Rsa15
    A suite of algorithms that uses RSA15 as Key-Wrap-algorithm
    and 128-Bit (16 bytes) for encryption algorithms.
    - SymmetricSignatureAlgorithm - HmacSha1
      (http://www.w3.org/2000/09/xmldsig#hmac-sha1)
    - SymmetricEncryptionAlgorithm - Aes128
      (http://www.w3.org/2001/04/xmlenc#aes128-cbc)
    - AsymmetricSignatureAlgorithm - RsaSha1
      (http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    - AsymmetricKeyWrapAlgorithm - KwRsa15
      (http://www.w3.org/2001/04/xmlenc#rsa-1_5)
    - AsymmetricEncryptionAlgorithm - Rsa15
      (http://www.w3.org/2001/04/xmlenc#rsa-1_5)
    - KeyDerivationAlgorithm - PSha1
      (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1)
    - DerivedSignatureKeyLength - 128 (16 bytes)
    - MinAsymmetricKeyLength - 1024 (128 bytes)
    - MaxAsymmetricKeyLength - 2048 (256 bytes)
    - CertificateSignatureAlgorithm - Sha1

    If a certificate or any certificate in the chain is not signed with
    a hash that is Sha1 or stronger than the certificate shall be rejected.
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
    AsymmetricSignatureURI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    secure_channel_nonce_length = 16

    signature_key_size = 16
    symmetric_key_size = 16
    deprecated = True
    asymmetric_padding_size = 11
    asymmetric_signer = SignerRsa
    asymmetric_verifier = VerifierRsa
    symmetric_signer = SignerAesCbc
    symmetric_verifier = VerifierAesCbc
    encrypt_function = staticmethod(uacrypto.encrypt_rsa15)
    decrypt_function = staticmethod(uacrypto.decrypt_rsa15)
    p_hash = staticmethod(uacrypto.p_sha1)
    encrypt_asymmetric = staticmethod(uacrypto.encrypt_rsa15)
    sign_asymmetric = staticmethod(uacrypto.sign_sha1)


class SecurityPolicyBasic256(RsaSecurityPolicy):
    """
    DEPRECATED, do not use anymore!

    Security Basic 256
    A suite of algorithms that are for 256-Bit (32 bytes) encryption,
    algorithms include:
    - SymmetricSignatureAlgorithm - HmacSha1
      (http://www.w3.org/2000/09/xmldsig#hmac-sha1)
    - SymmetricEncryptionAlgorithm - Aes256
      (http://www.w3.org/2001/04/xmlenc#aes256-cbc)
    - AsymmetricSignatureAlgorithm - RsaSha1
      (http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    - AsymmetricKeyWrapAlgorithm - KwRsaOaep
      (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p)
    - AsymmetricEncryptionAlgorithm - RsaOaep
      (http://www.w3.org/2001/04/xmlenc#rsa-oaep)
    - KeyDerivationAlgorithm - PSha1
      (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1)
    - DerivedSignatureKeyLength - 192 (24 bytes)
    - MinAsymmetricKeyLength - 1024 (128 bytes)
    - MaxAsymmetricKeyLength - 2048 (256 bytes)
    - CertificateSignatureAlgorithm - Sha1

    If a certificate or any certificate in the chain is not signed with
    a hash that is Sha1 or stronger than the certificate shall be rejected.
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    AsymmetricSignatureURI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    secure_channel_nonce_length = 32

    signature_key_size = 24
    symmetric_key_size = 32
    deprecated = True
    key_expiry_factor = 1.25
    asymmetric_padding_size = 42
    asymmetric_signer = SignerRsa
    asymmetric_verifier = VerifierRsa
    symmetric_signer = SignerAesCbc
    symmetric_verifier = VerifierAesCbc
    encrypt_function = staticmethod(uacrypto.encrypt_rsa_oaep)
    decrypt_function = staticmethod(uacrypto.decrypt_rsa_oaep)
    p_hash = staticmethod(uacrypto.p_sha1)
    encrypt_asymmetric = staticmethod(uacrypto.encrypt_rsa_oaep)
    sign_asymmetric = staticmethod(uacrypto.sign_sha1)


class SecurityPolicyBasic256Sha256(RsaSecurityPolicy):
    """
    Security Basic 256Sha256
    A suite of algorithms that uses Sha256 as Key-Wrap-algorithm
    and 256-Bit (32 bytes) for encryption algorithms.

    - SymmetricSignatureAlgorithm_HMAC-SHA2-256
      https://tools.ietf.org/html/rfc4634
    - SymmetricEncryptionAlgorithm_AES256-CBC
      http://www.w3.org/2001/04/xmlenc#aes256-cbc
    - AsymmetricSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA1
      http://www.w3.org/2001/04/xmlenc#rsa-oaep
    - KeyDerivationAlgorithm_P-SHA2-256
      http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256
    - CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - Basic256Sha256_Limits
        -> DerivedSignatureKeyLength: 256 bits
        -> MinAsymmetricKeyLength: 2048 bits
        -> MaxAsymmetricKeyLength: 4096 bits
        -> SecureChannelNonceLength: 32 bytes
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    AsymmetricSignatureURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    secure_channel_nonce_length = 32

    signature_key_size = 32
    symmetric_key_size = 32
    asymmetric_padding_size = 42
    asymmetric_signer = SignerSha256
    asymmetric_verifier = VerifierSha256
    symmetric_signer = SignerHMac256
    symmetric_verifier = VerifierHMac256
    encrypt_function = staticmethod(uacrypto.encrypt_rsa_oaep)
    decrypt_function = staticmethod(uacrypto.decrypt_rsa_oaep)
    p_hash = staticmethod(uacrypto.p_sha256)
    encrypt_asymmetric = staticmethod(uacrypto.encrypt_rsa_oaep)
    sign_asymmetric = staticmethod(uacrypto.sign_sha256)


def encrypt_asymmetric(pubkey, data, policy_uri):
    """
    Encrypt data with pubkey using an asymmetric algorithm.
    The algorithm is selected by policy_uri.
    Returns a tuple (encrypted_data, algorithm_uri)
    """
    for cls in [
        SecurityPolicyBasic256Sha256,
        SecurityPolicyBasic256,
        SecurityPolicyBasic128Rsa15,
        SecurityPolicyAes128Sha256RsaOaep,
        SecurityPolicyAes256Sha256RsaPss,
    ]:
        if policy_uri == cls.URI:
            return (cls.encrypt_asymmetric(pubkey, data), cls.AsymmetricEncryptionURI)
    if not policy_uri or policy_uri == SecurityPolicyNone.URI:
        return data, ""
    raise UaError(f"Unsupported security policy `{policy_uri}`")


class SecurityPolicyFactory:
    """
    Helper class for creating server-side SecurityPolicy.
    Server has one certificate and private key, but needs a separate
    SecurityPolicy for every client and client's certificate
    """

    def __init__(self, cls, mode, certificate=None, private_key=None, permission_ruleset=None, certificate_chain=None):
        self.cls = cls
        self.mode = mode
        self.certificate = certificate
        self.private_key = private_key
        self.certificate_chain = certificate_chain
        self.permission_ruleset = permission_ruleset

    def matches(self, uri, mode=None):
        return self.cls.URI == uri and (mode is None or self.mode == mode)

    def create(self, peer_certificate):
        return self.cls(
            peer_certificate,
            self.certificate,
            self.private_key,
            self.mode,
            permission_ruleset=self.permission_ruleset,
            host_cert_chain=self.certificate_chain,
        )


def sign_asymmetric(privkey, data, policy_uri: str | None):
    """
    Sign data with privkey using an asymmetric algorithm.
    The algorithm is selected by policy_uri.
    Returns a tuple (signature, algorithm_uri)
    """
    for cls in [
        SecurityPolicyBasic256Sha256,
        SecurityPolicyBasic256,
        SecurityPolicyBasic128Rsa15,
        SecurityPolicyAes128Sha256RsaOaep,
        SecurityPolicyAes256Sha256RsaPss,
    ]:
        if policy_uri == cls.URI:
            return (cls.sign_asymmetric(privkey, data), cls.AsymmetricSignatureURI)
    if not policy_uri or policy_uri == SecurityPolicyNone.URI:
        raise UaError("Cannot sign without a security policy that has a signature algorithm")
    raise UaError(f"Unsupported security policy `{policy_uri}`")


# policy, mode, security_level
SECURITY_POLICY_TYPE_MAP = {
    SecurityPolicyType.NoSecurity: [SecurityPolicyNone, MessageSecurityMode.None_, 0],
    SecurityPolicyType.Basic128Rsa15_Sign: [SecurityPolicyBasic128Rsa15, MessageSecurityMode.Sign, 1],
    SecurityPolicyType.Basic128Rsa15_SignAndEncrypt: [
        SecurityPolicyBasic128Rsa15,
        MessageSecurityMode.SignAndEncrypt,
        2,
    ],
    SecurityPolicyType.Basic256_Sign: [SecurityPolicyBasic256, MessageSecurityMode.Sign, 11],
    SecurityPolicyType.Basic256_SignAndEncrypt: [SecurityPolicyBasic256, MessageSecurityMode.SignAndEncrypt, 21],
    SecurityPolicyType.Basic256Sha256_Sign: [SecurityPolicyBasic256Sha256, MessageSecurityMode.Sign, 50],
    SecurityPolicyType.Basic256Sha256_SignAndEncrypt: [
        SecurityPolicyBasic256Sha256,
        MessageSecurityMode.SignAndEncrypt,
        70,
    ],
    SecurityPolicyType.Aes128Sha256RsaOaep_Sign: [SecurityPolicyAes128Sha256RsaOaep, MessageSecurityMode.Sign, 55],
    SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt: [
        SecurityPolicyAes128Sha256RsaOaep,
        MessageSecurityMode.SignAndEncrypt,
        75,
    ],
    SecurityPolicyType.Aes256Sha256RsaPss_Sign: [SecurityPolicyAes256Sha256RsaPss, MessageSecurityMode.Sign, 60],
    SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt: [
        SecurityPolicyAes256Sha256RsaPss,
        MessageSecurityMode.SignAndEncrypt,
        80,
    ],
}
