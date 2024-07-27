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
RESP_RESEND = b"\xfc"
RESP_DEC_ERR = b"ff"
FRAME_SIZE = 512
NUM_FRAMES = 1
FRAMES_SENT = 0

#constants from bootloader.h
IV_LEN = 16
MAC_LEN = 16
FRAME_MSG_LEN = 464
FRAME_BODY_LEN = 476

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

# def send_IV_and_tag(ser, debug=False):
#     # IV = metadata[0:16]
#     # tag = metadata[16:32]

#     # Handshake for update

#     ser.write(IV)
#     ser.write(tag)
#     print("Packaged IV and tag")

#     # Wait for an OK from the bootloader.
#     resp = ser.read(1)
#     print("Resp: ", resp)
#     if resp != RESP_OK:
#         raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))
    
#     # TODO: Remove the IV & TAG debug statements later
#     vi = b''
#     vi = ser.read(16)
#     print("IV: ", vi)

#     gat = b''
#     gat = ser.read(16)
#     print(f"Tag: {gat}")


# def send_ciphertext(ser, filepath, debug=False):
#     f = open(filepath, "rb")
#     data = f.read(512)

#     ciphertext = data[32:]
#     ser.write(ciphertext)

#     # Wait for an OK from the bootloader.
#     resp = ser.read(1)
#     print("Resp: ", resp)
#     if resp != RESP_OK:
#         raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))
    
#     # TODO: Remove the ciphertext debug statements later
#     ct = b''
#     ct = ser.read(480)
#     print("CT: ", ct)
#     print("Length: ", len(ct))

def calc_num_frames(file):
    if len(file) % FRAME_SIZE == 0:
        NUM_FRAMES = len(file) // FRAME_SIZE
    else:
        print("Something is wrong with the firmware protected file.")

def send_frame(ser, data, debug=False):
    print("SEND FRAME STARTED")
    global FRAMES_SENT

    IV = data[0:16]
    tag = data[16:32]
    ciphertext = data[32:]

    # print(len(IV))
    # print(len(tag))

    
    frame = IV + tag + ciphertext
    
    ser.write(frame)  # Write the frame...

    # if debug:
    #     print_hex(frame)

    print('waiting for a response')
    resp = ser.read(1)  # Wait for an OK from the bootloader
    print(resp)

    return resp

    # if debug:
    #     print("Resp: {}".format(ord(resp)))

    # # TODO: Remove the IV, TAG, & CIPHERTEXT debug statements later
    # vi = b''
    # vi = ser.read(16)
    # print("IV: ", vi)

    # gat = b''
    # gat = ser.read(16)
    # print(f"Tag: {gat}")

    # ct = b''
    # ct = ser.read(480)
    # print("CT: ", ct)
    # print("Length: ", len(ct))


def main():
    # declare the variables as global
    '''global FRAME_SIZE
    global NUM_FRAMES
    global FRAMES_SENT
    print("FRAMES SENT: ", FRAMES_SENT)'''
    #global FRAME_SIZE

    #send_IV_and_tag(ser)
    #send_ciphertext(ser, "tester.bin")
    f = open("protected_output.bin", "rb")
    data = f.read()
    calc_num_frames(data)
    wait_for_update()

    numFramesSent = FRAMES_SENT
    while FRAMES_SENT != NUM_FRAMES:
        print(FRAMES_SENT)
        current_frame = data[(numFramesSent * 512): (numFramesSent + 1) * 512]
        response = send_frame(ser, current_frame)

        while response != RESP_OK:
            if response == RESP_RESEND:
                response = send_frame(ser, current_frame)
            elif response == RESP_DEC_ERR:
                print("Potential attack. Aborting.")
                return
        
        # reading message type
        message_type = ser.read(1)
        
        if message_type == 0:
            for i in range(FRAME_MSG_LEN):
                print(ser.read(1))
            print("RELEASE MESSAGE: ", release_message)
        elif message_type == 1:
            body_data = ser.read(FRAME_BODY_LEN)
            print("BODY FRAME DATA: ", body_data)
        elif message_type == 2:
            end = ser.read(1)
            print("END MESSAGE TYPE LOL: ", end)
        FRAMES_SENT += 1

        
        print(message_type)

        
    ser.close()
    f.close()



def test_reader():
    pass
    
if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Firmware Update Tool")
    # parser.add_argument("--firmware", help="Path to firmware image to load.", required=True)
    main()
