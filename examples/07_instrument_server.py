"""
An instrument server built from OPC UA companion specifications.

Shows: importing the DI (Devices) and ADI (Analyser Devices) information models from NodeSet2 files, creating a
SpectrometerDeviceType instance (the model's mandatory children are created with it), filling in its identification
and spectral range, and adding a spectrum with its wavelength axis as variables of the instance. A client then browses
the instrument and reads the values.

The NodeSet2 files come from the `nodeset` git submodule of the repository (pinned UA-Nodeset release); run
`git submodule update --init nodeset` in a checkout first.

Run: python examples/07_instrument_server.py

Spec: OPC 10000-6 v1.05, Annex F (UANodeSet XML); OPC 10000-100 v1.05 (Devices, DI 1.05); OPC UA for Analyser Devices
(ADI) v1.01, 5.2.6 (SpectrometerDeviceType).
"""

import asyncio
import math
from pathlib import Path

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua

NODESETS = Path(__file__).resolve().parents[1] / "nodeset"
DI_URI = "http://opcfoundation.org/UA/DI/"
ADI_URI = "http://opcfoundation.org/UA/ADI/"
SPECTROMETER_DEVICE_TYPE = 1011


async def main() -> None:
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki")
        client = Client.quickstart(url, pki=directory / "client-pki")
        await server.init()
        idx = await server.register_namespace("urn:enginir:example:nir-instrument")
        await server.import_xml(NODESETS / "DI" / "Opc.Ua.Di.NodeSet2.xml")
        await server.import_xml(NODESETS / "ADI" / "Opc.Ua.Adi.NodeSet2.xml")
        di = await server.get_namespace_index(DI_URI)
        adi = await server.get_namespace_index(ADI_URI)

        spectrometer = await server.nodes.objects.add_object(
            ua.NodeId(0, idx), f"{idx}:NirSpectrometer", objecttype=ua.NodeId(SPECTROMETER_DEVICE_TYPE, adi)
        )
        identification = await spectrometer.get_child(f"{di}:Identification")
        await (await identification.get_child(f"{di}:Manufacturer")).write_value(ua.LocalizedText("engiNIR"))
        await (await identification.get_child(f"{di}:Model")).write_value(ua.LocalizedText("NIR-1700"))
        await (await identification.get_child(f"{di}:SerialNumber")).write_value("EX-0001")
        spectral_range = await spectrometer.get_child([f"{di}:ParameterSet", f"{adi}:SpectralRange"])
        await spectral_range.write_value(ua.Variant([ua.Range(Low=900.0, High=1700.0)], ua.VariantType.ExtensionObject))

        wavelengths = [900.0 + 50.0 * i for i in range(17)]
        absorbance = [0.2 + 0.5 * math.exp(-(((nm - 1450.0) / 80.0) ** 2)) for nm in wavelengths]
        await spectrometer.add_variable(idx, "Wavelengths", wavelengths)
        await spectrometer.add_variable(idx, "Absorbance", absorbance)
        await pair(directory / "server-pki", directory / "client-pki", client.application_uri)

        async with server, client:
            device = client.get_node(spectrometer.nodeid)
            print(
                "children:",
                [bn.Name for bn in await asyncio.gather(*(c.read_browse_name() for c in await device.get_children()))][
                    :6
                ],
            )
            ident = await device.get_child(f"{di}:Identification")
            model = await (await ident.get_child(f"{di}:Model")).read_value()
            print("model:", model.Text)
            axis = await (await device.get_child(f"{idx}:Wavelengths")).read_value()
            spectrum = await (await device.get_child(f"{idx}:Absorbance")).read_value()
            peak = max(range(len(spectrum)), key=spectrum.__getitem__)
            print(f"absorbance peak {spectrum[peak]:.2f} at {axis[peak]:.0f} nm")
            ranges = await (await device.get_child([f"{di}:ParameterSet", f"{adi}:SpectralRange"])).read_value()
            print("spectral range:", ranges[0].Low, "to", ranges[0].High, "nm")
    print("OK 07_instrument_server")


if __name__ == "__main__":
    asyncio.run(main())
