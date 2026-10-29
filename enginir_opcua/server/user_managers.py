from __future__ import annotations

import asyncio
import logging
import os
import stat
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.crypto import uacrypto, users_file
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.ua.uaerrors import ConfigurationError

if TYPE_CHECKING:
    from .internal_server import InternalServer

_logger = logging.getLogger(__name__)

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


class FileUserManager(UserManager):
    """
    Users from a users file (TOML or JSON): name, role and a salted scrypt hash of the password. The hash runs on a
    worker thread. An unknown user and a wrong password give the same answer and cost the same. The file is read
    again when it changed, at most once per `reload_interval` seconds, at a login; a file that no longer parses
    keeps the previous users and is logged. Anonymous tokens get the read-only role when `anonymous` is true.
    """

    def __init__(self, path: str | Path, anonymous: bool = True) -> None:
        self.path = Path(path)
        self.anonymous = anonymous
        self.reload_interval = 1.0
        self.accepted_token_types = frozenset(
            {ua.UserTokenType.UserName, *([ua.UserTokenType.Anonymous] if anonymous else [])}
        )
        self._users: dict[str, users_file.UserRecord] = {}
        self._signature: tuple[int, int] | None = None
        self._checked = time.monotonic()
        self._load()

    def _warn_if_readable(self) -> None:
        try:
            mode = self.path.stat().st_mode
        except OSError:
            return
        if os.name == "posix" and mode & 0o077:
            _logger.warning(
                "The users file %s is readable by other users (mode %o); password hashes allow offline guessing, "
                "use chmod 600",
                self.path,
                stat.S_IMODE(mode),
            )

    def _stat(self) -> tuple[int, int] | None:
        try:
            info = self.path.stat()
        except OSError:
            return None
        return info.st_mtime_ns, info.st_size

    def _load(self) -> None:
        records = users_file.read_users(self.path)
        self._users = {record.name: record for record in records}
        self._signature = self._stat()
        self._warn_if_readable()

    def _refresh(self) -> None:
        now = time.monotonic()
        if now - self._checked < self.reload_interval:
            return
        self._checked = now
        signature = self._stat()
        if signature is None or signature == self._signature:
            return
        try:
            self._load()
        except ConfigurationError as error:
            self._signature = signature
            _logger.error("%s; keeping the users read before", error)
        else:
            _logger.info("Read the users file %s again", self.path)

    def _check(self, username: str | None, password: str | None) -> User | None:
        if username is None:
            return User(role=UserRole.Anonymous) if self.anonymous else None
        record = self._users.get(username)
        stored = record.password_hash if record is not None else users_file.dummy_hash()
        matched = users_file.verify_password(password or "", stored)
        if record is None or password is None or not matched:
            return None
        return User(role=users_file.ROLES[record.role], name=record.name)

    def get_user(
        self,
        iserver: "InternalServer",
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        self._refresh()
        return self._check(username, password)

    async def authenticate(
        self,
        iserver: "InternalServer",
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        self._refresh()
        if username is None:
            return self._check(None, None)
        return await asyncio.to_thread(self._check, username, password)
