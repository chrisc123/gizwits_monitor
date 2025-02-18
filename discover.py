#!/usr/bin/env python3

"""
discover_devices.py

A script to demonstrate Gizwits LAN device discovery:
- Broadcast discovery (default): sends to 255.255.255.255
- Directed discovery: sends to a specific IP address

Usage:
    python discover_devices.py [--timeout 2.0] [--ip IP] [--port 12141]

Examples:
    python discover_devices.py  # Broadcast discovery
    python discover_devices.py --ip 192.168.1.100  # Directed discovery
"""

import argparse
import asyncio
import binascii
import socket
import struct
import time
import logging 

logger = logging.getLogger(__name__)

def _hex_to_ascii_uid(hex_uid: str) -> str:
    """Convert hex UID (44 chars representing 22 bytes) to ASCII (22 chars)"""
    try:
        return binascii.unhexlify(hex_uid).decode('ascii')
    except (binascii.Error, UnicodeDecodeError):
        return hex_uid

# Minimal parse logic for a Gizwits "04" response
# We'll just reuse parse_response_prefix for the prefix.
def parse_response_prefix(data: bytes):
    """
    Parse a Gizwits packet prefix:
      00 00 00 03 <varlen> flag cmd(2 bytes) payload
    Return (cmd, payload).
    """
    if not data.startswith(b"\x00\x00\x00\x03"):
        raise ValueError("Missing 00 00 00 03 prefix.")
    idx = 4

    # decode varlen
    length_val = 0
    shift = 0
    while True:
        if idx >= len(data):
            raise ValueError("Incomplete varlen.")
        b_i = data[idx]
        idx += 1
        length_val |= (b_i & 0x7F) << shift
        shift += 7
        if (b_i & 0x80) == 0:
            break

    if idx + 1 + 2 > len(data):
        raise ValueError("Not enough data for flag+cmd after varlen.")

    # read flag
    flag = data[idx]
    idx += 1

    # read 2-byte cmd
    cmd = data[idx:idx+2]
    idx += 2

    payload = data[idx:]
    return cmd, payload

def parse_varlen_field(data: bytes, offset: int) -> tuple[bytes, int]:
    """
    Parse a variable length field from the data starting at offset.
    Returns (field_data, new_offset)
    """
    if offset + 2 > len(data):
        return None, offset
    
    field_len = int.from_bytes(data[offset:offset+2], 'big')
    offset += 2
    
    if offset + field_len > len(data):
        return None, offset
        
    return data[offset:offset+field_len], offset + field_len

def parse_cstring(data: bytes, offset: int) -> tuple[str, int]:
    """
    Parse a null-terminated string starting at offset.
    Returns (string, new_offset)
    """
    end = offset
    while end < len(data) and data[end] != 0:
        end += 1
    
    if end >= len(data):
        return "", end
        
    return data[offset:end].decode('ascii', errors='ignore'), end + 1

def parse_discovery_response(data: bytes) -> dict:
    """
    Parse a discovery response packet (cmd=0x04).
    Format:
    <varlen_UID><UID>
    <varlen_MAC><MAC>
    <varlen_FW_VER><FW_VER>
    <varlen_PROD_KEY><PROD_KEY>
    <MCU_ATTRS> 
    <API_SERVER>\0
    <GAGENT_VER>\0
    """
    try:
        cmd, payload = parse_response_prefix(data)
        if cmd != b"\x00\x04":
            return None
            
        result = {}
        offset = 0
        
        # Variable length fields
        uid, offset = parse_varlen_field(payload, offset)
        if uid:
            result['uid'] = uid.hex()
            result['uid_ascii'] = _hex_to_ascii_uid(result['uid'])
            
        mac, offset = parse_varlen_field(payload, offset)
        if mac:
            result['mac'] = mac.hex(':')
            
        fw_ver, offset = parse_varlen_field(payload, offset)
        if fw_ver:
            result['firmware_version'] = fw_ver.decode('ascii', errors='ignore')
            
        prod_key, offset = parse_varlen_field(payload, offset)
        if prod_key:
            result['product_key'] = prod_key.decode('ascii', errors='ignore')
            
        # Raw MCU attributes (need to confirm format)
        if offset + 8 <= len(payload):
            result['mcu_attrs_raw'] = payload[offset:offset+8].hex()
            offset += 8
            
        # Null-terminated strings at end
        api_server, offset = parse_cstring(payload, offset)
        if api_server:
            result['api_server'] = api_server
            
        gizwits_ver, offset = parse_cstring(payload, offset)
        if gizwits_ver:
            result['gizwits_version'] = gizwits_ver
            
        return result
        
    except Exception as e:
        logger.error("Error parsing discovery response: %s", e)
        return None

DISCOVERY_REQUEST = b"\x00\x00\x00\x03\x03\x00\x00\x03"  # 8 bytes (cmd=03)

async def discover_devices(
    ip: str = "255.255.255.255",
    port: int = 12414,
    timeout: float = 2.0,
    retry_count: int = 3,
    retry_delay: float = 0.3
):
    """
    Send multiple discovery packets to improve reliability.
    
    Args:
        ip: Target IP (255.255.255.255 for broadcast)
        port: UDP port
        timeout: Total time to wait for responses
        retry_count: Number of discovery packets to send
        retry_delay: Delay between packets in seconds
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if ip == "255.255.255.255":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    sock.bind(("0.0.0.0", 0))
    sock.setblocking(False)

    # Track unique devices by IP to avoid duplicates
    devices = {}
    start_time = time.time()

    # Send discovery packets with delays
    for i in range(retry_count):
        if i > 0:
            await asyncio.sleep(retry_delay)
            
        logger.info("Sending discovery packet %d/%d to %s:%d", 
                    i + 1, retry_count,
                    ip, port)
        sock.sendto(DISCOVERY_REQUEST, (ip, port))

        # Process responses until next packet or timeout
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                break
                
            # Time until next packet or final timeout
            if i < retry_count - 1:
                wait_until = start_time + (i + 1) * retry_delay
                remaining = wait_until - time.time()
                if remaining <= 0:
                    break
            else:
                remaining = timeout - elapsed

            try:
                data, (src_ip, src_port) = sock.recvfrom(2048)
            except BlockingIOError:
                await asyncio.sleep(min(0.05, remaining))
                continue
            except Exception as e:
                logger.error("Error receiving data: %s", e)
                break

            try:
                parsed = parse_discovery_response(data)
                if parsed:
                    # Store device info keyed by IP
                    devices[src_ip] = {
                        'ip': src_ip,
                        'port': src_port,
                        **parsed
                    }
                    logger.info("Found device at %s:%d", src_ip, src_port)

            except Exception as e:
                logger.error("Error processing response: %s", e)
                continue

    sock.close()
    return list(devices.values())

async def main():
    parser = argparse.ArgumentParser(description="Gizwits LAN Device Discovery")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Total time to wait for responses")
    parser.add_argument("--ip", default="255.255.255.255",
                        help="IP address (default: broadcast)")
    parser.add_argument("--port", type=int, default=12414,
                        help="UDP port for discovery")
    parser.add_argument("--retries", type=int, default=3,
                        help="Number of discovery packets to send")
    parser.add_argument("--retry-delay", type=float, default=0.3,
                        help="Delay between discovery packets in seconds")
    args = parser.parse_args()

    discovered = await discover_devices(
        ip=args.ip,
        port=args.port,
        timeout=args.timeout,
        retry_count=args.retries,
        retry_delay=args.retry_delay
    )

    if not discovered:
        print("No devices discovered.")
    else:
        print(f"\nDiscovered {len(discovered)} device(s):")
        for dev in discovered:
            print(f"\nDevice at {dev['ip']}:{dev.get('port', '?')}")
            print(f"  UID: {dev.get('uid', '?')} (ASCII: {dev.get('uid_ascii', '?')})")
            print(f"  MAC Address: {dev.get('mac', '?')}")
            print(f"  Product Key: {dev.get('product_key', '?')}")
            print(f"  Firmware Version: {dev.get('firmware_version', '?')}")
            print(f"  Gizwits GAgent Version: {dev.get('gizwits_version', '?')}")
            print(f"  API Server: {dev.get('api_server', '?')}")
            print(f"  MCU Attributes (raw): {dev.get('mcu_attrs_raw', '?')}")

if __name__=="__main__":
    asyncio.run(main())
