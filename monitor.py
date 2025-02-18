# monitor.py
import asyncio
import logging
import sys

from gizwits_lan.device_manager import DeviceManager

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

async def main():
    if len(sys.argv) < 3:
        print("Usage: python monitor.py <device_ip> <product_key>")
        sys.exit(1)

    ip = sys.argv[1]
    product_key = sys.argv[2]

    # directory with your <product_key>.json file
    definitions_dir = "definitions"

    manager = DeviceManager(definitions_dir=definitions_dir)

    device = await manager.create_device(
        ip=ip,
        product_key=product_key
    )
    await device.connect()  # Explicit connection
    
    print(f"Connected to device at {ip}. Monitoring indefinitely. Press Ctrl+C to exit.")
    try:
        while True:
            await asyncio.sleep(3600)  # sleep in big chunks, read loop does the rest
    except KeyboardInterrupt:
        print("Exiting monitor.")
    finally:
        await device.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
