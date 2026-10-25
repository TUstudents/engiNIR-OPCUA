from enum import IntEnum


class SecurityPolicyType(IntEnum):
    """
    The supported types of SecurityPolicy.

    "NoSecurity"
    "Basic128Rsa15_Sign"
    "Basic128Rsa15_SignAndEncrypt"
    "Basic256_Sign"
    "Basic256_SignAndEncrypt"
    "Basic256Sha256_Sign"
    "Basic256Sha256_SignAndEncrypt"
    "Aes128Sha256RsaOaep_Sign"
    "Aes128Sha256RsaOaep_SignAndEncrypt"
    "Aes256Sha256RsaPss_Sign"
    "Aes256Sha256RsaPss_SignAndEncrypt"
    """

    NoSecurity = 0
    Basic128Rsa15_Sign = 1
    Basic128Rsa15_SignAndEncrypt = 2
    Basic256_Sign = 3
    Basic256_SignAndEncrypt = 4
    Basic256Sha256_Sign = 5
    Basic256Sha256_SignAndEncrypt = 6
    Aes128Sha256RsaOaep_Sign = 7
    Aes128Sha256RsaOaep_SignAndEncrypt = 8
    Aes256Sha256RsaPss_Sign = 9
    Aes256Sha256RsaPss_SignAndEncrypt = 10
