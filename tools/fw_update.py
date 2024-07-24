#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Updater Tool

There are 3 frame types; Start Msg, Data Msg, and End Msg
Frame size is fixed to 512 bytes, no matter the msg type
All data is encrypted except IV and Tag.


A Start MSG-type (message type 0) frame consists of:
- IV 0x10  (16 bytes)
- Tag 0x10 (16 bytes)
- Ciphertext (480 bytes)
    - Type 0x01
    - Size 0x04
    - Version number 0x02
    - Release Message 473 bytes → padded with pkcs-7

A Data msg type (message type 1) frame consists of:
- IV - 16 bytes (0x10)
- Tag - 16 bytes (0x10)
- Ciphertext (480 bytes)
    - Type 0x01
    - Data - 479 bytes → padded with pkcs-7

An end msg type (message type 2) frame consists of:
- IV- 16 bytes (0x10)
- Tag- 16 bytes (0x10)
- Ciphertext (480 bytes)
    - 0x1 message type
    - PKCS-7 padding or null bytes 479 bytes


In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero byte
"""

import argparse
from pwn import *
import time
import serial

from util import *

ser = serial.Serial("/dev/ttyACM0", 115200)


RESP_OK = b"\x00"
FRAME_SIZE = 512

# def send_metadata(ser, metadata, debug=False):
#     assert(len(metadata) == 512)


#     msg_type = u8(metadata[1], endian="little")
#     size = u16(metadata[1:3], endian="little")
#     SIZE = u16(metadata[19:21], endian="little")
#     print(f"Message Type: {msg_type}\nTotal Size (all data): {size} bytes")
#     #print(f"Version: {version}\nSize: {size} bytes\n")

#     # Handshake for update
#     ser.write(b"U")

#     print("Waiting for bootloader to enter update mode...")
#     while ser.read(1).decode() != "U":
#         print("got a byte")
#         pass

#     # Send size and version to bootloader.
#     if debug:
#         print(metadata)

#     ser.write(metadata)

#     # Wait for an OK from the bootloader.
#     resp = ser.read(1)
#     if resp != RESP_OK:
#         raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))
# commented for now, don't want to delete it before testing


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    # metadata = firmware_blob[:SIZE]
    # firmware = firmware_blob[SIZE:]

    # send_metadata(ser, metadata, debug=debug)

    for idx, frame_start in enumerate(range(0, len(firmware_blob), FRAME_SIZE)):
        frame = firmware_blob[frame_start : frame_start + FRAME_SIZE]
        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing its page.
    # ser.write(p16(0x0000, endian='big'))
    # resp = ser.read(1)  # Wait for an OK from the bootloader
    # if resp != RESP_OK:
    #     raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    # print(f"Wrote zero length frame (2 bytes)")

    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    update(ser=ser, infile=args.firmware, debug=args.debug)
    ser.close()
