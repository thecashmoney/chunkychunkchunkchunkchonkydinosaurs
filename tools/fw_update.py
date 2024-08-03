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
    """
    Waits until the bootloader sends a U back to the python and then starts.
    Run AFTER you start the c program (by restarting board or gdb)
    """

    ser.write(b"U")
    print("Waiting for bootloader to enter update mode...")
    resp =  ser.read(1).decode()
    while resp != "U":
        resp = ser.read(1).decode()
    print("Connection established ;)")

def calc_num_frames(filedata):
    """
    Returns the number of frames in the protected firmware
    """

    if len(filedata) % FRAME_SIZE == 0:
        frames = len(filedata) // FRAME_SIZE
        return frames
    else:
        print("Something is wrong with the firmware protected file.")

def send_frame(ser, data, debug=False):
    """
    Sends a frame including:
        IV: 16 bytes
        tag: 16 bytes
        ciphertext: 480 bytes
    """
    IV = data[0:16]
    tag = data[16:32]
    ciphertext = data[32:]

    # Sending the entire frame
    frame = IV + tag + ciphertext

    ser.write(frame)  # Write the frame...  


def read_byte():
    """
    There are sometimes random null bytes that the bootloader sends us
    so we just ignore them lol (we never send 0x00 from bootloader --> python)
    """
    byte = ser.read(1)
    while byte == b'\x00':
        byte = ser.read(1)
    return byte

def update(infile):
    """
    Initializes the update process.
    Sends data frame by frame, waiting after decryption and again
    after verification to send another frame
    """

    num_frames = 0

    f = open(infile, "rb")
    data = f.read()
    f.close()
    num_frames = calc_num_frames(data)
    frames_sent = 0

    print("Number of frames:", num_frames)
    # Waiting for the bootloader to respond
    wait_for_update()

    while frames_sent != num_frames:
        # A frame is trying to be sent (not sent yet)
        print("Frame.")
        current_frame = data[frames_sent * 512: (frames_sent + 1) * 512]
        send_frame(ser, current_frame)
        frames_sent += 1
    
        # This is whether the bootloader decrypted the frame correctly or not
        decrypt_response = read_byte()

        # Script to resend the frame while the decryption didn't work, but tolerance is usually 0 so doesn't do much
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
        bootloader_status = read_byte()
        if bootloader_status == VERSION_ERROR:
            print("Version error")
            return
        elif bootloader_status == TYPE_ERROR:
            print("Problem recieving frame")
            return
        elif bootloader_status == STOP:
            print("Done.")
            return
        elif bootloader_status != RESP_OK:
            print("Response error")
            return
        
    ser.close()

if __name__ == "__main__":
    #calc num frames works
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    args = parser.parse_args()

    update(args.infile)
