import asyncio
import getpass
import io
import stat
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, tools, ua
from enginir_opcua.config import ClientConfig, ServerConfig
from enginir_opcua.crypto import pki, users_file
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.uacrypto import certificate_thumbprint
from tests.conftest import find_free_port
from tests.pki import make_identity
from tests.setup.conftest import make_credentials


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = tools.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def own_thumbprint(directory: Path) -> str:
    return certificate_thumbprint((directory / "own" / "certs" / pki.CERTIFICATE_NAME).read_bytes()).hex()


def init_server(capsys: pytest.CaptureFixture[str], directory: Path, *extra: str) -> tuple[int, str, str]:
    return run(capsys, "init", "server", str(directory), *extra)


def test_the_k_commands_are_registered() -> None:
    assert {"init", "trust", "pki", "pair", "user"} <= set(tools.COMMANDS)


def test_init_server_writes_a_pki_directory_and_a_config(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = init_server(capsys, tmp_path / "plant", "--endpoint", "opc.tcp://127.0.0.1:4850/x/")
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith("created  ") and lines[0].endswith(str(tmp_path / "plant" / "pki"))
    assert f"thumbprint {own_thumbprint(tmp_path / 'plant' / 'pki')}" in lines[1]
    assert "expires 20" in lines[1]
    assert lines[2].endswith("server.toml")
    assert any(line.startswith("next     enginir-opcua user add") for line in lines)
    config = ServerConfig.from_toml(tmp_path / "plant" / "server.toml")
    assert config.pki == str(tmp_path / "plant" / "pki")
    assert config.endpoint == "opc.tcp://127.0.0.1:4850/x/"
    assert list((tmp_path / "plant" / "pki" / "trusted" / "certs").iterdir()) == []
    assert stat.S_IMODE((tmp_path / "plant" / "server.toml").stat().st_mode) == 0o600


def test_init_client_and_the_certificate_carries_the_uri(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run(
        capsys, "init", "client", str(tmp_path / "c"), "--url", "opc.tcp://localhost:4850", "--name", "Probe"
    )
    assert code == 0 and "next" not in out
    config = ClientConfig.from_toml(tmp_path / "c" / "client.toml")
    assert config.name == "Probe"
    from cryptography import x509

    certificate = x509.load_der_x509_certificate(
        (tmp_path / "c" / "pki" / "own" / "certs" / pki.CERTIFICATE_NAME).read_bytes()
    )
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert config.application_uri in names.get_values_for_type(x509.UniformResourceIdentifier)


def test_init_keeps_the_certificate_and_refuses_to_replace_the_config(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    init_server(capsys, tmp_path / "plant")
    before = own_thumbprint(tmp_path / "plant" / "pki")
    code, _, err = init_server(capsys, tmp_path / "plant")
    assert code == 1 and "already exists; use --force" in err
    code, out, _ = init_server(capsys, tmp_path / "plant", "--force")
    assert code == 0 and "kept     " in out
    assert own_thumbprint(tmp_path / "plant" / "pki") == before


def test_init_development_needs_a_loopback_endpoint(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = init_server(
        capsys, tmp_path / "d", "--profile", "development", "--endpoint", "opc.tcp://0.0.0.0:4840"
    )
    assert code == 1 and "loopback" in err and "server.endpoint" in err
    assert not (tmp_path / "d").exists()


def seed(directory: Path, name: str = "peer") -> tuple[str, bytes]:
    pki.create_directories(directory)
    identity = make_identity(name)
    return certificate_thumbprint(identity.der).hex(), identity.der


def reject(directory: Path, der: bytes) -> str:
    thumbprint = certificate_thumbprint(der).hex()
    (directory / "rejected" / "certs" / f"{thumbprint}.der").write_bytes(der)
    return thumbprint


def test_trust_moves_a_rejected_certificate_by_thumbprint(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    _, der = seed(tmp_path)
    thumbprint = reject(tmp_path, der)
    code, out, err = run(capsys, "trust", thumbprint.upper(), "--pki", str(tmp_path))
    assert code == 0
    assert out.startswith(f"trusted  {thumbprint}  CN=peer") and "expires" in out
    assert (tmp_path / "trusted" / "certs" / f"{thumbprint}.der").read_bytes() == der
    assert not (tmp_path / "rejected" / "certs" / f"{thumbprint}.der").exists()
    assert "next connection" in err
    code, out, _ = run(capsys, "trust", thumbprint, "--pki", str(tmp_path))
    assert code == 1


def test_trust_takes_a_unique_prefix_and_a_path(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    _, der = seed(tmp_path)
    thumbprint = reject(tmp_path, der)
    prefix = ":".join(thumbprint[i : i + 2] for i in range(0, 12, 2))
    assert run(capsys, "trust", prefix, "--pki", str(tmp_path))[0] == 0
    other = make_identity("fromfile")
    path = tmp_path / "x.der"
    path.write_bytes(other.der)
    code, out, _ = run(capsys, "trust", str(path), "--pki", str(tmp_path))
    assert code == 0 and "CN=fromfile" in out
    assert (tmp_path / "trusted" / "certs" / f"{certificate_thumbprint(other.der).hex()}.der").exists()
    code, out, _ = run(capsys, "trust", str(path), "--pki", str(tmp_path))
    assert code == 0 and "already trusted" in out


def test_trust_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    pki.create_directories(tmp_path)
    code, _, err = run(capsys, "trust", "ab12cd34", "--pki", str(tmp_path))
    assert code == 1 and f"no certificate with thumbprint 'ab12cd34' in {tmp_path / 'rejected' / 'certs'}" in err
    assert "pki list" in err
    code, _, err = run(capsys, "trust", "zz", "--pki", str(tmp_path))
    assert (code == 1 and "not a certificate" in err) or "thumbprint" in err
    junk = tmp_path / "junk.der"
    junk.write_bytes(b"nope")
    code, _, err = run(capsys, "trust", str(junk), "--pki", str(tmp_path))
    assert code == 1 and "is not a certificate" in err
    code, _, err = run(capsys, "trust", "abcdef12", "--pki", str(tmp_path / "missing"))
    assert code == 1 and "is not a PKI directory" in err


def test_trust_ambiguous_prefix_and_ca_and_expired_warnings(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    pki.create_directories(tmp_path)
    ca = make_identity("ca", ca=True)
    expired = make_identity(
        "old",
        not_before=ca.certificate.not_valid_before_utc.replace(year=2020),
        not_after=ca.certificate.not_valid_before_utc.replace(year=2021),
    )
    reject(tmp_path, ca.der)
    reject(tmp_path, expired.der)
    code, _, err = run(capsys, "trust", certificate_thumbprint(ca.der).hex(), "--pki", str(tmp_path))
    assert code == 0 and "CA certificate" in err
    code, _, err = run(capsys, "trust", certificate_thumbprint(expired.der).hex(), "--pki", str(tmp_path))
    assert code == 0 and "expired on 2021" in err


def test_trust_ambiguous(capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from enginir_opcua import cli_setup

    monkeypatch.setattr(cli_setup, "_thumbprint", lambda certificate: "aaaaaaaa" + f"{certificate.serial_number:x}"[:8])
    pki.create_directories(tmp_path)
    for name in ("aaaaaaaa11", "aaaaaaaa22"):
        (tmp_path / "rejected" / "certs" / f"{name}.der").write_bytes(make_identity(name).der)
    code, _, err = run(capsys, "trust", "aaaaaaaa", "--pki", str(tmp_path))
    assert code == 1 and "matches 2 certificates" in err


def test_pki_list(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    asyncio.run(make_credentials(tmp_path, "urn:test:me", pki.SERVER_USAGE))
    peer = make_identity("peer")
    (tmp_path / "trusted" / "certs" / "peer.der").write_bytes(peer.der)
    (tmp_path / "rejected" / "certs" / ".abc.der.1234.tmp").write_bytes(b"temporary")
    (tmp_path / "rejected" / "certs" / "junk.der").write_bytes(b"junk")
    code, out, err = run(capsys, "pki", "list", "--pki", str(tmp_path))
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith("own ") and own_thumbprint(tmp_path) in lines[0] and "urn:test:me" in lines[0]
    assert any(line.startswith("trusted ") and certificate_thumbprint(peer.der).hex() in line for line in lines)
    assert lines[-1] == "trusted/crl: 0 lists   issuer/crl: 0 lists"
    assert "junk.der" in err and ".tmp" not in err


def test_pki_list_empty_and_missing(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    pki.create_directories(tmp_path)
    code, out, _ = run(capsys, "pki", "list", "--pki", str(tmp_path))
    assert code == 0 and out.splitlines()[0] == "no certificates"
    code, _, err = run(capsys, "pki", "list", "--pki", str(tmp_path / "none"))
    assert code == 1 and "is not a PKI directory; create one with enginir-opcua init" in err


def test_pki_alone_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as error:
        tools.main(["pki"])
    assert error.value.code == 2


def test_pair_trusts_both_ways_and_always_warns(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    asyncio.run(make_credentials(tmp_path / "s", "urn:test:s", pki.SERVER_USAGE))
    asyncio.run(make_credentials(tmp_path / "c", "urn:test:c", pki.CLIENT_USAGE))
    code, out, err = run(capsys, "pair", str(tmp_path / "s"), str(tmp_path / "c"))
    assert code == 0
    assert err.startswith("warning: pair makes both applications trust each other's certificate")
    assert f"trusted  {own_thumbprint(tmp_path / 'c')}" in out and f"{tmp_path / 's' / 'trusted' / 'certs'}" in out
    assert (tmp_path / "s" / "trusted" / "certs" / f"{own_thumbprint(tmp_path / 'c')}.der").exists()
    assert (tmp_path / "c" / "trusted" / "certs" / f"{own_thumbprint(tmp_path / 's')}.der").exists()


def test_pair_writes_nothing_when_one_side_has_no_certificate(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    asyncio.run(make_credentials(tmp_path / "s", "urn:test:s", pki.SERVER_USAGE))
    pki.create_directories(tmp_path / "c")
    code, _, err = run(capsys, "pair", str(tmp_path / "s"), str(tmp_path / "c"))
    assert code == 1 and "no application certificate in own/certs; create it with enginir-opcua init" in err
    assert list((tmp_path / "s" / "trusted" / "certs").iterdir()) == []
    assert "warning: pair" in err


def feed(monkeypatch: pytest.MonkeyPatch, *answers: str) -> None:
    replies = iter(answers)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(replies))


def test_user_add_list_remove(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "users.toml"
    feed(monkeypatch, "correct horse", "correct horse")
    code, out, _ = run(capsys, "user", "add", str(path), "alice", "--role", "user")
    assert code == 0 and out == f"added user 'alice' (role user) to {path}\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    (record,) = users_file.read_users(path)
    assert users_file.verify_password("correct horse", record.password_hash)
    assert "correct horse" not in path.read_text()
    feed(monkeypatch, "another pass", "another pass")
    assert run(capsys, "user", "add", str(path), "root", "--role", "admin")[0] == 0
    feed(monkeypatch, "x" * 9, "x" * 9)
    code, _, err = run(capsys, "user", "add", str(path), "alice", "--role", "user")
    assert code == 1 and "already exists" in err and "--replace" in err
    feed(monkeypatch, "x" * 9, "x" * 9)
    assert run(capsys, "user", "add", str(path), "alice", "--role", "user", "--replace")[0] == 0
    code, out, _ = run(capsys, "user", "list", str(path))
    assert out.splitlines() == ["alice user", "root admin"] and "scrypt" not in out
    assert run(capsys, "user", "remove", str(path), "alice")[1] == f"removed user 'alice' from {path}\n"
    code, _, err = run(capsys, "user", "remove", str(path), "alice")
    assert code == 1 and "no user 'alice'" in err
    assert [r.name for r in users_file.read_users(path)] == ["root"]


def test_user_add_checks_the_password(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "users.toml"
    feed(monkeypatch, "short", "short")
    code, _, err = run(capsys, "user", "add", str(path), "alice", "--role", "user")
    assert code == 1 and "password" in err and not path.exists()
    feed(monkeypatch, "correct horse", "different one")
    code, _, err = run(capsys, "user", "add", str(path), "alice", "--role", "user")
    assert code == 1 and "do not match" in err and not path.exists()


def test_user_add_reads_the_password_from_stdin(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "users.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("correct horse\n"))
    assert run(capsys, "user", "add", str(path), "alice", "--role", "security_admin", "--password-stdin")[0] == 0
    (record,) = users_file.read_users(path)
    assert record.role == "security_admin" and users_file.verify_password("correct horse", record.password_hash)


def test_user_add_leaves_a_broken_file_alone(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "users.toml"
    path.write_text("version = 7\n")
    feed(monkeypatch, "correct horse", "correct horse")
    code, _, err = run(capsys, "user", "add", str(path), "alice", "--role", "user")
    assert code == 1 and "unsupported version 7" in err
    assert path.read_text() == "version = 7\n"


def test_user_add_has_no_password_option() -> None:
    with pytest.raises(SystemExit):
        tools.main(["user", "add", "f.toml", "alice", "--role", "user", "--password", "x"])


async def test_an_in_process_trust_reaches_a_running_store(tmp_path: Path) -> None:
    pki.create_directories(tmp_path)
    store = TrustStore.from_pki_directory(tmp_path)
    await store.load()
    peer = make_identity("late")
    (tmp_path / "rejected" / "certs" / f"{certificate_thumbprint(peer.der).hex()}.der").write_bytes(peer.der)
    assert not store.snapshot.is_trusted(peer.certificate)
    assert tools.main(["trust", certificate_thumbprint(peer.der).hex(), "--pki", str(tmp_path)]) == 0
    assert store.snapshot.is_trusted(peer.certificate)


async def test_init_pair_and_serve_from_the_generated_config(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    port = find_free_port()
    url = f"opc.tcp://127.0.0.1:{port}/plant/"
    assert await asyncio.to_thread(tools.main, ["init", "server", str(tmp_path / "s"), "--endpoint", url]) == 0
    assert await asyncio.to_thread(tools.main, ["init", "client", str(tmp_path / "c"), "--url", url]) == 0
    assert tools.main(["pair", str(tmp_path / "s" / "pki"), str(tmp_path / "c" / "pki")]) == 0
    capsys.readouterr()
    server = Server(config=ServerConfig.from_toml(tmp_path / "s" / "server.toml"))
    await server.init()
    async with server:
        async with Client(config=ClientConfig.from_toml(tmp_path / "c" / "client.toml")) as client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
