from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.crypto import uacrypto
from enginir_opcua.crypto.permission_rules import User, UserRole

if TYPE_CHECKING:
    from .internal_server import InternalServer


ALL_TOKEN_TYPES: frozenset[ua.UserTokenType] = frozenset(
    {ua.UserTokenType.Anonymous, ua.UserTokenType.UserName, ua.UserTokenType.Certificate}
)


class UserManager:
    """
    Decides who the user of a Session is. `accepted_token_types` lists the kinds of UserIdentityToken the server
    offers on its endpoints; a token of any other kind is rejected before `get_user` is asked.
    """

    accepted_token_types: frozenset[ua.UserTokenType] = ALL_TOKEN_TYPES

    def get_user(
        self,
        iserver: "InternalServer",
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        raise NotImplementedError

    async def authenticate(
        self,
        iserver: "InternalServer",
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        """
        Decide who the user of a Session is, without blocking the event loop. The default calls get_user, so a
        manager that only implements get_user keeps working; a manager that does slow work (a password hash, a
        database) overrides this method and runs it on a worker thread.
        """
        return self.get_user(iserver, username=username, password=password, certificate=certificate)


async def authenticate_user(
    manager: Any,
    iserver: "InternalServer",
    username: str | None = None,
    password: str | None = None,
    certificate: Any = None,
) -> User | None:
    """Ask a user manager, which may be any object with get_user or authenticate, for the user of a login."""
    authenticate = getattr(manager, "authenticate", None)
    if authenticate is not None:
        result: User | None = await authenticate(iserver, username=username, password=password, certificate=certificate)
        return result
    result = manager.get_user(iserver, username=username, password=password, certificate=certificate)
    return result


class AnonymousReadOnlyUserManager(UserManager):
    """
    The default user manager: accepts Anonymous tokens as the read-only role and nothing else.
    """

    accepted_token_types = frozenset({ua.UserTokenType.Anonymous})

    def get_user(
        self,
        iserver: "InternalServer",
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        return User(role=UserRole.Anonymous)


class PermissiveUserManager(UserManager):
    """
    INSECURE, for tests and demos only: any user name with any password is accepted, `admin` and `Admin` as
    Admin and every other login, Anonymous included, as User. It is never the default; pass it to the server
    explicitly.
    """

    def get_user(
        self,
        iserver: "InternalServer",
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        if username in ("admin", "Admin"):
            return User(role=UserRole.Admin)
        return User(role=UserRole.User)


class CertificateUserManager(UserManager):
    """
    Certificate user manager, takes a certificate handler with its associated users and provides those users.
    A user is found by the certificate of an X509 token, or by the certificate of the SecureChannel for an
    Anonymous token. A login without a registered certificate is refused unless `allow_anonymous` is set, which
    gives it the read-only role.
    """

    accepted_token_types = frozenset({ua.UserTokenType.Anonymous, ua.UserTokenType.Certificate})

    def __init__(self, allow_anonymous: bool = False) -> None:
        self._trusted_certificates: dict[str, dict[str, Any]] = {}
        self.allow_anonymous = allow_anonymous

    async def add_role(
        self,
        certificate_path: Path,
        user_role: UserRole,
        name: str,
        format: str | None = None,
    ) -> None:
        certificate = await uacrypto.load_certificate(certificate_path, format)
        if name is None:
            raise KeyError

        user = User(role=user_role, name=name)

        if name in self._trusted_certificates:
            logging.warning(
                "certificate with name %s attempted to be added multiple times, only the last version will be kept.",
                name,
            )
        self._trusted_certificates[name] = {"certificate": uacrypto.der_from_x509(certificate), "user": user}

    def get_user(
        self,
        iserver: "InternalServer",
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        correct_users = [
            prospective_certificate["user"]
            for prospective_certificate in self._trusted_certificates.values()
            if certificate is not None and certificate == prospective_certificate["certificate"]
        ]
        if correct_users:
            return correct_users[0]
        if self.allow_anonymous and username is None:
            return User(role=UserRole.Anonymous)
        return None

    def pinned_certificates(self) -> list[Any]:
        return [uacrypto.x509_from_der(entry["certificate"]) for entry in self._trusted_certificates.values()]

    async def add_user(self, certificate_path: Path, name: str, format: str | None = None) -> None:
        await self.add_role(certificate_path=certificate_path, user_role=UserRole.User, name=name, format=format)

    async def add_admin(self, certificate_path: Path, name: str, format: str | None = None) -> None:
        await self.add_role(certificate_path=certificate_path, user_role=UserRole.Admin, name=name, format=format)

    async def add_security_admin(self, certificate_path: Path, name: str, format: str | None = None) -> None:
        await self.add_role(
            certificate_path=certificate_path, user_role=UserRole.SecurityAdmin, name=name, format=format
        )
