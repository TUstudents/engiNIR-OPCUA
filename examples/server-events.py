import asyncio
import logging

from enginir_opcua import ua
from enginir_opcua.server import Server

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger("enginir_opcua")


async def main():
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/enginir-opcua/server/")
    # setup our own namespace, not really necessary but should as spec
    uri = "http://examples.freeopcua.github.io"
    idx = await server.register_namespace(uri)
    # populating our address space
    myobj = await server.nodes.objects.add_object(idx, "MyObject")

    # Creating a custom event: Approach 1
    # The custom event object automatically will have members from its parent (BaseEventType)
    etype = await server.create_custom_event_type(
        idx,
        "MyFirstEvent",
        ua.ObjectIds.BaseEventType,
        [("MyNumericProperty", ua.VariantType.Float), ("MyStringProperty", ua.VariantType.String)],
    )
    myevgen = await server.get_event_generator(etype, myobj)

    # Creating a custom event: Approach 2
    custom_etype = await server.nodes.base_event_type.add_object_type(2, "MySecondEvent")
    await custom_etype.add_property(2, "MyIntProperty", ua.Variant(0, ua.VariantType.Int32))
    await custom_etype.add_property(2, "MyBoolProperty", ua.Variant(True, ua.VariantType.Boolean))
    mysecondevgen = await server.get_event_generator(custom_etype, myobj)

    async with server:
        count = 0
        while True:
            await asyncio.sleep(1)
            myevgen.event.Message = ua.LocalizedText(f"MyFirstEvent {count}")
            myevgen.event.Severity = count
            myevgen.event.MyNumericProperty = count
            myevgen.event.MyStringProperty = f"Property {count}"
            await myevgen.trigger()
            await mysecondevgen.trigger(message=f"MySecondEvent {count}")

            count += 1


if __name__ == "__main__":
    asyncio.run(main())
