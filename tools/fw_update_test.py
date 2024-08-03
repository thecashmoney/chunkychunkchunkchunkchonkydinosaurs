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
RESP_DEC_OK = b"\x05"
RESP_RESEND = b"\x06"
RESP_DEC_ERR = b"\x07"
VERSION_ERROR = b'\x08'
TYPE_ERROR  = b'\x09'
FRAME_SIZE = 512
STOP = b'\x10'


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

    # print(len(IV))
    # print(len(tag))
    # frame = IV + tag + ciphertext
    # print("IV: ", IV)
    # print("tag: ", tag)
    # print("ctext: ", ciphertext)

    frame = IV + tag + ciphertext

    ser.write(frame)  # Write the frame...  

    #resp = read_byte()
    #print("Bootloader responded with: ", resp)

    #return resp

def read_byte():
    byte = ser.read(1)
    while byte == b'\x00':
        byte = ser.read(1)
    return byte

def main():
    num_frames = 0

    f = open("protected_output.bin", "rb")
    data = f.read()
    f.close()
    num_frames = calc_num_frames(data)
    frames_sent = 0

    print("Number of frames:", num_frames)
    wait_for_update()

    while frames_sent != num_frames:
        current_frame = data[frames_sent * 512: (frames_sent + 1) * 512]
        send_frame(ser, current_frame)
        frames_sent += 1
    

        # if(response != RESP_OK):
        #     #screaming sobbing dying
        #     send_frame(ser, current_frame)
            #sends back the current frame if the response is not OK

        # Reads 0 if successful decryption, or RESP_RESEND if not
        decrypt_response = read_byte()

        while decrypt_response!= RESP_DEC_OK:
            if decrypt_response == RESP_RESEND:
                send_frame(ser, current_frame)
                decrypt_response = read_byte()
            elif decrypt_response == RESP_DEC_ERR:
                print("Potential attack. Aborting.")
                return
            else:
                print("Bootloader error encountered.")
                return

            
        
        # reading message type
        message_type = read_byte()
        if message_type == VERSION_ERROR:
            print("Go kill yourself")
            return
        elif message_type == TYPE_ERROR:
            print("Problem recieving frame")
            return
        elif message_type == STOP:
            print("Done.")
            return
        elif message_type != RESP_OK:
            print("Response error")
            return
        
    ser.close()

if __name__ == "__main__":
    #calc num frames works
    main()

    