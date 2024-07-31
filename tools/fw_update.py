#!/usr/bin/env python
# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.


#final FW update: removed print statements + reminder to document this better


import argparse
from pwn import *
import time
import serial

# Remove print statements
# Flash release message
from util import *


ser = serial.Serial("/dev/ttyACM0", 115200)


#CONSTANTS FOR MESSAGE/ERROR CODES
STOP = b'\x03'
RESP_OK = b"\x04"
RESP_DEC_OK = b"\x05"
RESP_RESEND = b"\x06"
RESP_DEC_ERR = b"\x07"
VERSION_ERROR = b'\x08'
TYPE_ERROR  = b"\x09"


#frame size: constant 512 bytes
FRAME_SIZE = 512


#constants from bootloader.h
IV_LEN = 16
MAC_LEN = 16
FRAME_MSG_LEN = 464
FRAME_BODY_LEN = 476


# Establishes a serial connection with bootloader.c
def wait_for_update():
   ser.write(b"U")
   print("Waiting for bootloader to enter update mode...")
   resp =  ser.read(1).decode()
   while resp != "U":
       resp = ser.read(1).decode()
   print("Connection established...")


# Calculate the total number of frames that are to be sent
def calc_num_frames(filedata):
   if len(filedata) % FRAME_SIZE == 0:
       frames = len(filedata) // FRAME_SIZE
       return frames
   else:
       print("Something is wrong with the protected firmware file...")


# Send one frame to bootloader.c
def send_frame(ser, data, debug=False):
   # Define IV, Tag, and Ciphertext as slices of provided data (512 bytes provided)
   IV = data[0:16]

   tag = data[16:32]

   ciphertext = data[32:]


   #frame is the combination of IV, tag, and ciphertext
   frame = IV + tag + ciphertext


   ser.write(frame)  # Write the frame to bootloader.c
   # resp = read_byte()
   # return resp


# Function to read one (non null) byte from serial
def read_byte():
   byte = ser.read(1)
   while byte == b'\x00':
       byte = ser.read(1)
   return byte


# Main function: sends all frames from protected_output.bin to bootloader.c, one frame at a time
def main():
    # Defining variables for number of start msg frames sent, total number of frames, and number of body frames sent
    frames_sent = 0
    num_frames = 0

    # open protected firmware file to obtain metadata and firmware data
    f = open("protected_output.bin", "rb")
    data = f.read()
    f.close()

    # calculate the number of frames total (for metadata and firmware data)
    num_frames = calc_num_frames(data)

    # call wait for update to establish a connection with bootloader
    wait_for_update()


   # cycle through frames, send frames to bootloader.c
    while (frames_sent) != num_frames:
        current_frame = data[frames_sent * 512: (frames_sent + 1) * 512]
        send_frame(ser, current_frame)
        frames_sent += 1


        # Determine whether frame resend/abort is needed.
        # Reads 0 if successful decryption, or RESP_RESEND if not
        decrypt_response = read_byte()
        print("I want to end my life, but the decrypt response is: ", decrypt_response)



        while decrypt_response != RESP_DEC_OK:
            if decrypt_response == RESP_RESEND:
                send_frame(ser, current_frame)
                decrypt_response = read_byte()
            elif decrypt_response == RESP_DEC_ERR:
                print("Potential attack. Aborting.")
                return
            else:
                print("Bootloader error encountered.")
                return

        # checking for potential error/attack
        frame_status = read_byte()
        print("FRAME STATUS RAHHHH", frame_status)
        if frame_status == TYPE_ERROR or frame_status == VERSION_ERROR:
            print("error encountered")
            return
        elif frame_status == STOP:
            print("Complete")
            return
        elif frame_status != RESP_OK:
            print("Unknown frame status, terminating")
            return 


    ser.close()


# run main function
if __name__ == "__main__":
   main()





