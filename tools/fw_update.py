#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.


import argparse
from pwn import *
import time
import serial

from util import *

ser = serial.Serial("/dev/ttyACM0", 115200)
RESP_OK = b"\x04"
ERROR = b"\x05"
# RESP_RESEND = b"\x06"
# RESP_DEC_ERR = b"\x07"
# VERSION_ERROR = b'\x08'
# TYPE_ERROR  = b'\x09'
# STOP = b'\x10'
FRAME_SIZE = 512


#constants from bootloader.h
IV_LEN = 16
MAC_LEN = 16
FRAME_MSG_LEN = 464
FRAME_BODY_LEN = 476


# WORKING
def wait_for_update():
    ser.write(b"U")
    print("Waiting for bootloader to enter update mode...")
    resp =  ser.read(1).decode()
    while resp != "U":
        resp = ser.read(1).decode()
    print("Connection established ;)")

def calc_num_frames(filedata):
    if len(filedata) % FRAME_SIZE == 0:
        frames = len(filedata) // FRAME_SIZE
        return frames
    else:
        print("Something is wrong with the firmware protected file.")

def send_frame(ser, data, debug=False):
    # print("SEND FRAME IS RUNNING")
    IV = data[0:16]
    tag = data[16:32]
    ciphertext = data[32:]

    print("IV: ", IV.hex())
    print("TAG: ", tag.hex())
    print("CIPHERTEXT: ", ciphertext.hex())

    frame = IV + tag + ciphertext

    ser.write(frame)  # Write the frame...  


def read_byte():
    byte = ser.read(1)
    while byte == b'\x00':
        byte = ser.read(1)
    return byte

def main():
    num_frames = 0

    with open("/home/hacker/chunkychunkchunkchunkchonkydinosaurs/tools/protected_output.bin", "rb") as f:
        data = f.read()
        f.close()
    num_frames = calc_num_frames(data)
    frames_sent = 0

    print("Number of frames:", num_frames)
    wait_for_update()
    

    while frames_sent != num_frames:
        print("Frame.")
        current_frame = data[frames_sent * 512: (frames_sent + 1) * 512]
        send_frame(ser, current_frame)
    
        # if(response != RESP_OK):
        #     #screaming sobbing dying
        #     send_frame(ser, current_frame)
            #sends back the current frame if the response is not OK

        # Reads 0 if successful decryption, or RESP_RESEND if not
        decrypt_response = read_byte()
        print("Decrypt response: ", decrypt_response)
        if decrypt_response != RESP_OK:
            return
            
        # reading message type
        type_error = read_byte()
        print("Type byte", type_error)
        if type_error != RESP_OK:
            return


        if(frames_sent == 0): 
            version_error = read_byte()  
            print("Version byte", version_error)   
            if version_error != RESP_OK:
                return
        
        frames_sent += 1
                    
    ser.close()

if __name__ == "__main__":
    #calc num frames works
    main()
