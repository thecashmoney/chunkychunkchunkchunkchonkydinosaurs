#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.


import argparse
from pwn import *
import time
import serial

from util import *

ser = serial.Serial("/dev/ttyACM0", 115200)
MSG_START = b'\x01'
MSG_BODY = b'\x02'
MSG_END = b'\x03'
RESP_OK = b"\x03"
RESP_DEC_OK = b"\x05"
RESP_RESEND = b"\x06"
RESP_DEC_ERR = b"\x07"
VERSION_ERROR = b'\x08'
TYPE_ERROR  = b'\x09'
FRAME_SIZE = 512
NUM_FRAMES = 1
FRAMES_SENT = 0


#constants from bootloader.h
IV_LEN = 16
MAC_LEN = 16
FRAME_MSG_LEN = 464
FRAME_BODY_LEN = 476


# WORKING
def wait_for_update():
    ser.write(b"U")
    print("Waiting for bootloader to enter update mode...")
    ctr = 1
    no =  ser.read(1).decode()
    while no != "U":
        print(f"byte: {ctr}")
        print("One of the initial bytes:", no)
        ctr += 1
        no = ser.read(1).decode()
    print("Bootloader responded with a", no)

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
    print('waiting for a response to sending the frame (in send_frame)')

    resp = read_byte()
    print("Bootloader responded with: ", resp)

    return resp

def read_byte():
    byte = ser.read(1)
    while byte == b'\x00':
        byte = ser.read(1)
        print("null byte >:(")
    return byte
    #cringe

def main():
    start_frames_sent = 0
    num_frames = 0
    body_frames_sent = 0

    f = open("protected_output.bin", "rb")
    data = f.read()
    f.close()
    num_frames = calc_num_frames(data)

    print("Number of frames:", num_frames)
    wait_for_update()

    while (start_frames_sent + body_frames_sent) != num_frames:
        total_sent = (start_frames_sent + body_frames_sent)
        print("Frames sent:", start_frames_sent + body_frames_sent)
        current_frame = data[total_sent * 512: (total_sent + 1) * 512]
        response = send_frame(ser, current_frame) 
    

        # if(response != RESP_OK):
        #     #screaming sobbing dying
        #     send_frame(ser, current_frame)
            #sends back the current frame if the response is not OK

        # Reads 0 if successful decryption, or RESP_RESEND if not
        decrypt_response = read_byte()
        print("Decrypt status:", decrypt_response)


        #print(response)
        while decrypt_response!= RESP_DEC_OK:
            print("Resending: response: ", response)
            if decrypt_response == RESP_RESEND:
                response = send_frame(ser, current_frame)
                decrypt_response = read_byte()
                print("Decrypt status:", decrypt_response)
            elif decrypt_response == RESP_DEC_ERR:
                print("Potential attack. Aborting.")
                return
            else:
                print("Bootloader error encountered. Responded with", decrypt_response)
                return

            
        
        # reading message type
        message_type = read_byte()
        print("Message type: ", message_type)
        if message_type == VERSION_ERROR:
            print("Go kill yourself")
            return
        elif message_type == TYPE_ERROR:
            print("Type error")
            return

        msg_str = b""
        body_str = b""
        if message_type == MSG_START:
            start_frames_sent += 1
            msg_len = u32(ser.read(4), endian="little")
            print("Message len:", msg_len)
            print("Calculation factor:", start_frames_sent * FRAME_MSG_LEN)
            if msg_len > start_frames_sent * FRAME_MSG_LEN:
                for _ in range(FRAME_MSG_LEN):
                    msg_str += ser.read(1)
            else:
                for _ in range((msg_len % FRAME_MSG_LEN) if msg_len % FRAME_MSG_LEN != 0 else FRAME_MSG_LEN):
                    msg_str += ser.read(1)
            print("Release message:", msg_str)
        elif message_type == MSG_BODY:
            body_frames_sent += 1
            body_len = u32(ser.read(4), endian="little")
            if body_len > body_frames_sent * FRAME_BODY_LEN:
                for _ in range(FRAME_BODY_LEN):
                    body_str += ser.read(1)
            else:
                for _ in range((body_len % FRAME_BODY_LEN) if body_len % FRAME_BODY_LEN != 0 else FRAME_BODY_LEN):
                    body_str += ser.read(1)
            print("Firmware:", body_str)
        elif message_type == MSG_END:
            print("END MESSAGE TYPE LOL: ", message_type)
            return
        else:
            print("noooooooooooooooooooooooooooooooooooooooooooo", message_type)
        # print(ser.read(1))
        # print(message_type)
    ser.close()



def test():
    wait_for_update()
    f = open("protected_output.bin", "rb")
    total_data = f.read()
    original_data = total_data[:512]
    new_data = b''
    
    response = send_frame(ser, total_data[:512])
    if response == b'\x00':
        ser.read(1)
        ser.read(1)
        for _ in range(512):
            value = ser.read(1)
            #print(value, end="")
            new_data += value
    else:
        print("Error response", response)

    print()
    print("Original:", original_data)
    print("New:", new_data)
    print("Are they equal?", original_data == new_data)

if __name__ == "__main__":
    #calc num frames works
    main()

    