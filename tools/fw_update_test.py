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
RESP_DEC_ERR = b"\xff"
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
        ctr += 1
        no = ser.read(1).decode()
    print(no)

def calc_num_frames(file):
    if len(file) % FRAME_SIZE == 0:
        NUM_FRAMES = len(file) // FRAME_SIZE
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
    print('waiting for a response (in send_frame)')
    resp = ser.read(1)  # Wait for an OK from the bootloader
    #print("Reponse from bootloader:", resp)

    return resp

def main():
    # declare the variables as global
    '''global FRAME_SIZE
    global NUM_FRAMES
    global FRAMES_SENT
    print("FRAMES SENT: ", FRAMES_SENT)'''
    #global FRAME_SIZE

    frames_sent = 0
    num_frames = 1

    #send_IV_and_tag(ser)
    #send_ciphertext(ser, "tester.bin")
    f = open("protected_output.bin", "rb")
    data = f.read()
    calc_num_frames(data)
    wait_for_update()

    while frames_sent != num_frames:
        print("Frames sent:", frames_sent)
        current_frame = data[(frames_sent * 512): (frames_sent + 1) * 512]
        response = send_frame(ser, current_frame)

        #i think we need another if statement checking response of original frame
        #before decryption, we send a uart write so if that one is not ok then other ones
        # also wont be ok
        #idk what im doing lowk
        #this has gone past the point of making sense

        if(response != RESP_OK):
            #screaming sobbing dying
            send_frame(ser, current_frame)
            #sends back the current frame if the response is not OK

        # Reads 0 if successful decryption, or RESP_RESEND if not
        decrypt_success = ser.read(1)
        print("Decrypt status:", decrypt_success)


        #print(response)
        while decrypt_success != RESP_OK:
            print("Resending: response: ", response)
            if response == RESP_RESEND:
                response = send_frame(ser, current_frame)
                decrypt_success = ser.read(1)
            elif response == RESP_DEC_ERR:
                print("Potential attack. Aborting.")
                return
            else:
                print("Bootloader error encountered.")
                return
        
        frames_sent += 1
            
        
        # reading message type
        message_type = ser.read(1)
        
        if message_type == b'\x00':
            for i in range(FRAME_MSG_LEN):
                print("printing start frame", ser.read(1))
        elif message_type == b'\x01':
            body_data = ser.read(FRAME_BODY_LEN)
            print("BODY FRAME DATA: ", body_data)
        elif message_type == b'\x02':
            end = ser.read(1)
            print("END MESSAGE TYPE LOL: ", end)
        else:
            print("Message type:", message_type)

        
        # print(message_type)

        
    ser.close()
    f.close()



def test_reader():
    pass
    
if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Firmware Update Tool")
    # parser.add_argument("--firmware", help="Path to firmware image to load.", required=True)
    main()
