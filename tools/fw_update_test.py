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
#OFFSET = 0
NUM_FRAMES = 1
FRAMES_SENT = 0


'''IV = b''
tag = b''

ctr = 0

for i in range(16):
    IV += p8(ctr, endian="little")
    tag += p8(ctr + 1, endian="little")
    ctr += 1'''


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

def calc_num_frames(file):
    if len(file) % FRAME_SIZE == 0:
        NUM_FRAMES = len(file) // FRAME_SIZE
    else:
        NUM_FRAMES = len(file) // FRAME_SIZE + 1

def send_frame(ser, data, debug=False):
    global FRAMES_SENT

    IV = data[0:16]
    tag = data[16:32]
    ciphertext = data[32:]

    frame = IV + tag + ciphertext
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))
    else:
        FRAMES_SENT += 1

    if debug:
        print("Resp: {}".format(ord(resp)))

    # TODO: Remove the IV, TAG, & CIPHERTEXT debug statements later
    vi = b''
    vi = ser.read(16)
    print("IV: ", vi)

    gat = b''
    gat = ser.read(16)
    print(f"Tag: {gat}")

    ct = b''
    ct = ser.read(480)
    print("CT: ", ct)
    print("Length: ", len(ct))


def main():
    # declare the variables as global
    '''global FRAME_SIZE
    global NUM_FRAMES
    global FRAMES_SENT
    print("FRAMES SENT: ", FRAMES_SENT)'''

    #send_IV_and_tag(ser)
    #send_ciphertext(ser, "tester.bin")
    calc_num_frames("tester.bin")
    f = open("tester.bin", "rb")
    data = f.read()
    wait_for_update()

    numFramesSent = FRAMES_SENT
    while FRAMES_SENT != NUM_FRAMES:
        send_frame(ser, data[(numFramesSent * 512): (numFramesSent + 1) * 512])
    ser.close()


if __name__ == "__main__":
    main()
