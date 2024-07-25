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
FRAME_SIZE = 512
OFFSET = 0
NUM_FRAMES = 1
FRAMES_SENT = 0


IV = b''
tag = b''

ctr = 0

for i in range(16):
    IV += p8(ctr, endian="little")
    tag += p8(ctr + 1, endian="little")
    ctr += 1


# WORKING
def wait_for_update():
    ser.write(b"U")
    print("Waiting for bootloader to enter update mode...")
    ctr = 1
    while ser.read(1).decode() != "U":
        print(f"byte: {ctr}")
        ctr += 1
        pass

def send_IV_and_tag(ser, debug=False):
    # IV = metadata[0:16]
    # tag = metadata[16:32]

    # Handshake for update

    ser.write(IV)
    ser.write(tag)
    print("Packaged IV and tag")

    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    print("Resp: ", resp)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))
    
    # TODO: Remove the IV & TAG debug statements later
    vi = b''
    vi = ser.read(16)
    print("IV: ", vi)

    gat = b''
    gat = ser.read(16)
    print(f"Tag: {gat}")


def send_ciphertext(ser, filepath, debug=False):
    f = open(filepath, "rb")
    data = f.read(512)

    ciphertext = data[32:]
    ser.write(ciphertext)

    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    print("Resp: ", resp)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))
    
    # TODO: Remove the ciphertext debug statements later
    ct = b''
    ct = ser.read(480)
    print("CT: ", ct)
    print("Length: ", len(ct))


if __name__ == "__main__":
    wait_for_update()
    send_IV_and_tag(ser)
    send_ciphertext(ser, "tester.bin")
    ser.close()
