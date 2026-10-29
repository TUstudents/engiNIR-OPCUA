"""
PubSub over UDP, publisher and subscriber in one process (experimental).

Shows: a PublishedDataSet fed from a dictionary, a WriterGroup and DataSetWriter that publish it as UADP messages on
a fixed interval, and a DataSetReader whose sink receives the fields. The messages are unicast on the loopback
interface. PubSub has no message security in this library: anybody who can send datagrams to a subscriber can feed
it, so use it on a trusted network only and bind to the interface you mean (the bind rule is in docs/usage/pubsub).

Run: python examples/10_pubsub.py

Spec: OPC 10000-14 v1.05, 6.2.3 (PublishedDataSet), 6.2.4 (DataSetWriter), 6.2.6 (WriterGroup), 6.2.9
(DataSetReader), 7.2.4 (UADP message mapping) and 7.3.2 (UDP).
"""

import asyncio

from _common import free_port

from enginir_opcua import pubsub, ua
from enginir_opcua.pubsub.udp import UdpSettings

DATASET = "Spectrum"
PUBLISHER_ID = ua.UInt16(1)
WRITER_GROUP_ID = ua.UInt16(1)
DATASET_WRITER_ID = ua.UInt16(32)


def metadata() -> pubsub.DataSetMeta:
    meta = pubsub.DataSetMeta.Create(DATASET)
    meta.add_scalar("Scan", ua.VariantType.Int32)
    meta.add_scalar("Peak", ua.VariantType.Double)
    return meta


class Sink:
    def __init__(self) -> None:
        self.received: asyncio.Queue[dict[str, object]] = asyncio.Queue()

    async def on_dataset_received(self, meta: pubsub.DataSetMeta, fields: list[pubsub.DataSetValue]) -> None:
        values = {field.Name: field.Value.Value.Value for field in fields if field.Value and field.Value.Value}
        self.received.put_nowait(values)

    async def on_state_change(self, meta: pubsub.DataSetMeta, state: ua.PubSubState) -> None:
        print("reader state:", state.name)


async def main() -> None:
    url = f"opc.udp://127.0.0.1:{free_port()}"
    sink = Sink()

    dataset = pubsub.PublishedDataSet.Create(DATASET, metadata())
    source = dataset.get_source()
    source.datasources[DATASET] = {
        "Scan": ua.DataValue(ua.Variant(ua.Int32(1))),
        "Peak": ua.DataValue(ua.Variant(1450.0, ua.VariantType.Double)),
    }
    publisher = pubsub.PubSubConnection.udp_uadp(
        "Publisher",
        PUBLISHER_ID,
        UdpSettings(Url=url),
        writer_groups=[
            pubsub.WriterGroup.new_uadp(
                "WriterGroup1",
                ua.UInt32(WRITER_GROUP_ID),
                publishing_interval=100,
                writer=[
                    pubsub.DataSetWriter.new_uadp("Writer1", DATASET, ua.UInt32(DATASET_WRITER_ID), datavalue=True)
                ],
            )
        ],
    )

    reader = pubsub.DataSetReader.new(
        ua.Variant(PUBLISHER_ID),
        WRITER_GROUP_ID,
        DATASET_WRITER_ID,
        metadata(),
        name="Reader1",
        subscribed=sink,
        enabled=True,
    )
    subscriber = pubsub.PubSubConnection.udp_uadp(
        "Subscriber",
        ua.UInt16(2),
        UdpSettings(Url=url),
        reader_groups=[pubsub.ReaderGroup.new("ReaderGroup1", [reader], enable=True)],
    )

    async with (
        pubsub.PubSub.new(connections=[subscriber]),
        pubsub.PubSub.new(connections=[publisher], datasets=[dataset]),
    ):
        async with asyncio.timeout(10):
            print("received:", await sink.received.get())
            source.datasources[DATASET]["Scan"] = ua.DataValue(ua.Variant(ua.Int32(3)))
            while (values := await sink.received.get())["Scan"] != 3:
                pass
            print("received:", values)
    print("OK 10_pubsub")


if __name__ == "__main__":
    asyncio.run(main())
