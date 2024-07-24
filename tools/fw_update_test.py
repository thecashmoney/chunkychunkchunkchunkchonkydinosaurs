#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.


import argparse
from pwn import *
import time
import serial

from util import *

ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x00"
FRAME_SIZE = 256

IV = []
tag = []

ctr = b"\x00"

for i in range(16):
    IV.append(ctr)
    tag.append(ctr + 1)
    ctr += 1


def wait_for_update():
    ser.write(b"U")
    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass


def send_IV_and_tag(ser, metadata, debug=False):
    # IV = metadata[0:16]
    # tag = metadata[16:32]
    
    print("Packaged IV and tag")

    # Handshake for update

    ser.write(IV)
    ser.write(tag)
    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))



if __name__ == "__main__":
    wait_for_update()
    send_IV_and_tag()
    ser.close()
