import asyncio
import json
import os
import stat
import time
from pathlib import Path

import pytest

from enginir_opcua.crypto import users_file
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.server.user_managers import FileUserManager
from enginir_opcua.ua.uaerrors import ConfigurationError

GOOD = "correct horse"


def _toml(*entries: str) -> str:
    return "version = 1\n" + "".join(entries)


def _entry(name: str, role: str, stored: str) -> str:
    return f'\n[[user]]\nname = "{name}"\nrole = "{role}"\npassword_hash = "{stored}"\n'


def test_hash_round_trip_and_format() -> None:
    stored = users_file.hash_password(GOOD)
    kind, n, r, p, salt, key = stored.split("$")
    assert (kind, n, r, p) == ("scrypt", "32768", "8", "1")
    assert len(key) == 44 and len(salt) == 24
    assert users_file.verify_password(GOOD, stored)
    assert not users_file.verify_password("wrong password", stored)
    assert users_file.hash_password(GOOD) != stored


@pytest.mark.parametrize(
    "stored",
    [
        pytest.param("plain", id="not_scrypt"),
        pytest.param("scrypt$100$8$1$AAAAAAAAAAAAAAAAAAAAAA==$" + "A" * 44, id="n_not_power_of_two_in_range"),
        pytest.param("scrypt$1073741824$8$1$AAAAAAAAAAAAAAAAAAAAAA==$" + "A" * 44, id="n_too_large"),
        pytest.param("scrypt$32768$8$1$AAAA$" + "A" * 44, id="salt_too_short"),
        pytest.param("scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAA", id="key_too_short"),
        pytest.param("scrypt$32768$x$1$AAAAAAAAAAAAAAAAAAAAAA==$" + "A" * 44, id="r_not_a_number"),
    ],
)
def test_a_malformed_or_unbounded_hash_is_refused(stored: str) -> None:
    with pytest.raises(ConfigurationError, match="scrypt"):
        users_file.parse_hash(stored)


def test_password_rules() -> None:
    users_file.check_password_rules("12345678")
    for bad in ("1234567", "x" * 1025):
        with pytest.raises(ConfigurationError, match="password"):
            users_file.check_password_rules(bad)


def test_users_file_round_trip_toml_and_json(tmp_path: Path) -> None:
    users = [
        users_file.UserRecord("alice", "user", users_file.hash_password(GOOD)),
        users_file.UserRecord("bob", "security_admin", users_file.hash_password(GOOD)),
    ]
    for name in ("users.toml", "users.json"):
        path = tmp_path / name
        users_file.write_users(path, users)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert users_file.read_users(path) == users
    assert json.loads((tmp_path / "users.json").read_text())["version"] == 1


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param('[[user]]\nname = "a"\n', "version", id="missing_version"),
        pytest.param("version = 2\n", "unsupported version 2", id="wrong_version"),
        pytest.param("version = 1\nextra = 1\n", "unknown", id="unknown_key"),
        pytest.param(
            _toml('\n[[user]]\nname = "a"\nrole = "user"\n'), "user 'a' \\(entry 1\\): password_hash", id="no_hash"
        ),
        pytest.param(_toml(_entry("a", "anonymous", "x")), "role", id="bad_role"),
        pytest.param(_toml(_entry(" a", "user", "x")), "name", id="name_with_space"),
        pytest.param("version = 1\n[[user]\n", "users.toml", id="syntax"),
    ],
)
def test_users_file_errors_name_the_file_user_and_entry(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "users.toml"
    path.write_text(text)
    with pytest.raises(ConfigurationError, match=message) as error:
        users_file.read_users(path)
    assert str(path) in str(error.value)


def test_duplicate_names_name_the_second_entry(tmp_path: Path) -> None:
    stored = users_file.hash_password(GOOD)
    path = tmp_path / "users.toml"
    path.write_text(_toml(_entry("a", "user", stored), _entry("a", "admin", stored)))
    with pytest.raises(ConfigurationError, match=r"user 'a' \(entry 2\): .*already"):
        users_file.read_users(path)


def _manager(tmp_path: Path, anonymous: bool = True) -> tuple[FileUserManager, Path]:
    path = tmp_path / "users.toml"
    users_file.write_users(
        path,
        [
            users_file.UserRecord("alice", "user", users_file.hash_password(GOOD)),
            users_file.UserRecord("root", "admin", users_file.hash_password(GOOD)),
        ],
    )
    return FileUserManager(path, anonymous=anonymous), path


async def test_file_user_manager_authenticates_and_maps_roles(tmp_path: Path) -> None:
    manager, _ = _manager(tmp_path)
    user = await manager.authenticate(None, username="alice", password=GOOD)
    assert user is not None and (user.name, user.role) == ("alice", UserRole.User)
    admin = await manager.authenticate(None, username="root", password=GOOD)
    assert admin is not None and admin.role == UserRole.Admin
    assert await manager.authenticate(None, username="alice", password="nope") is None
    assert await manager.authenticate(None, username="mallory", password=GOOD) is None
    assert await manager.authenticate(None, username="alice", password=None) is None
    certificate_login = await manager.authenticate(None, certificate=b"channel certificate")
    assert certificate_login is not None and certificate_login.role == UserRole.Anonymous


async def test_file_user_manager_anonymous_follows_the_setting(tmp_path: Path) -> None:
    manager, _ = _manager(tmp_path, anonymous=True)
    anonymous = await manager.authenticate(None)
    assert anonymous is not None and anonymous.role == UserRole.Anonymous
    assert ua_types(manager) == {"UserName", "Anonymous"}
    strict, _ = _manager(tmp_path, anonymous=False)
    assert await strict.authenticate(None) is None
    assert ua_types(strict) == {"UserName"}


def ua_types(manager: FileUserManager) -> set[str]:
    return {token.name for token in manager.accepted_token_types}


async def test_unknown_user_and_wrong_password_cost_a_hash_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, _ = _manager(tmp_path)
    calls: list[str] = []
    real = users_file.verify_password

    def counting(password: str, stored: str) -> bool:
        calls.append(stored)
        return real(password, stored)

    monkeypatch.setattr(users_file, "verify_password", counting)
    await manager.authenticate(None, username="alice", password="wrong")
    await manager.authenticate(None, username="mallory", password="wrong")
    assert len(calls) == 2


async def test_srv101_the_hash_does_not_block_the_event_loop(tmp_path: Path) -> None:
    manager, _ = _manager(tmp_path)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.005)
            ticks += 1

    task = asyncio.create_task(ticker())
    await manager.authenticate(None, username="alice", password=GOOD)
    task.cancel()
    assert ticks >= 3


async def test_file_user_manager_reloads_a_changed_file_and_keeps_the_old_set_on_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    manager, path = _manager(tmp_path)
    manager.reload_interval = 0.0
    users_file.write_users(path, [users_file.UserRecord("carol", "user", users_file.hash_password(GOOD))])
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert await manager.authenticate(None, username="carol", password=GOOD) is not None
    assert await manager.authenticate(None, username="alice", password=GOOD) is None
    path.write_text("version = 1\n[[user]\n")
    os.utime(path, (time.time() + 10, time.time() + 10))
    with caplog.at_level("ERROR"):
        assert await manager.authenticate(None, username="carol", password=GOOD) is not None
    assert str(path) in caplog.text


def test_file_user_manager_warns_about_a_readable_file(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    _, path = _manager(tmp_path)
    path.chmod(0o644)
    with caplog.at_level("WARNING"):
        FileUserManager(path)
    assert "readable" in caplog.text


def test_file_user_manager_needs_an_existing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"users\.toml"):
        FileUserManager(tmp_path / "users.toml")


def test_an_empty_users_file_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "users.toml"
    path.write_text("version = 1\n")
    assert users_file.read_users(path) == []
    assert isinstance(FileUserManager(path), FileUserManager)
