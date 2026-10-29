"""
Serving files and a directory, and moving files with a client.

Shows: Server.add_file for a file on disk (read only) and for an in-memory file that users may write, and
Server.add_directory for a directory tree that a user may change (create a file, read it, delete it). The client uses
UaFile and UaDirectory. Writing needs the "user" role.

Run: python examples/08_file_transfer.py

Spec: OPC 10000-20 v1.05, 4.2 (FileType: Open, Close, Read, Write, GetPosition, SetPosition) and 4.3
(FileDirectoryType: CreateDirectory, CreateFile, Delete, MoveOrCopy).
"""

import asyncio

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_file_transfer import UaDirectory, UaFile
from enginir_opcua.crypto.users_file import UserRecord, hash_password, write_users
from enginir_opcua.server.file_transfer import MemoryFile

READ = ua.OpenFileMode.Read.value
WRITE_NEW = ua.OpenFileMode.Write.value | ua.OpenFileMode.EraseExisting.value


async def main() -> None:
    with workdir() as directory:
        exports = directory / "exports"
        exports.mkdir()
        report = directory / "report.txt"
        report.write_text("calibration report: ok\n")
        users = directory / "users.toml"
        write_users(users, [UserRecord("operator", "user", hash_password("operator-secret"))])

        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki", users=users)
        client = Client.quickstart(url, pki=directory / "client-pki", username="operator", password="operator-secret")
        await server.init()
        await server.register_namespace("urn:enginir:example:files")
        objects = server.nodes.objects
        report_node = await server.add_file(objects, "Report", report, mime_type="text/plain")
        method_node = await server.add_file(objects, "Method", MemoryFile(b"{}"), writable=True, max_size=4096)
        tree_node = await server.add_directory(objects, "FileSystem", exports, writable=True)
        await pair(directory / "server-pki", directory / "client-pki", client.application_uri)

        async with server, client:
            async with UaFile(client.get_node(report_node.nodeid)) as remote:
                print("report:", (await remote.read()).decode().strip())

            method_file = client.get_node(method_node.nodeid)
            async with UaFile(method_file, WRITE_NEW) as remote:
                await remote.write(b'{"scans": 32, "resolution_nm": 5}')
            async with UaFile(method_file, READ) as remote:
                print("method:", (await remote.read()).decode())

            tree = UaDirectory(client.get_node(tree_node.nodeid))
            file_id, _ = await tree.create_file("scan-0001.csv")
            async with UaFile(client.get_node(file_id), WRITE_NEW) as remote:
                await remote.write(b"nm,absorbance\n1450,0.70\n")
            print("on the server's disk:", (exports / "scan-0001.csv").read_text().splitlines()[1])
            await tree.delete(file_id)
            print("after Delete:", sorted(path.name for path in exports.iterdir()))
    print("OK 08_file_transfer")


if __name__ == "__main__":
    asyncio.run(main())
