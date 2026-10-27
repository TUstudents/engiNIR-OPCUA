import sys

sys.path.insert(0, "..")
import logging

from enginir_opcua import Client, ua

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARN)

    client = Client("opc.tcp://admin@localhost:4840/enginir-opcua/server/")  # connect using a user
    try:
        client.connect()

        objects = client.nodes.objects
        folder = objects.add_folder("ns=2;i=3007", "2:Folder1")
        var = folder.add_variable("ns=2;i=3008", "2:Variable1", 3.45)

        results = client.delete_nodes([folder, var])
        try:
            # var.write_value(9.89) # just to check it does not work
            var.read_browse_name()
        except ua.UaStatusCodeError:
            print("The variable has been removed OK")

    finally:
        client.disconnect()
