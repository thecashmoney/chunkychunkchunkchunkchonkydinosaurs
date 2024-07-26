#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

7/22/24 - Elliott Jang and Oliver Beresford
Part 1: Start message encryption
- start_protect(startMsg, outputMsg, version, message)
Part 2: Data message encryption: Split into chonks first and then encrypt each chonk
Part 3: End message encryption

"""

import argparse
from pwn import *
from Crypto.Util.Padding import pad, unpad
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


RMmax = 464
DATAmax = 476


def ceildiv(a, b):
    return -(a // -b)

def protect_firmware(infile, version, message):

    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()
    index = start_protect(len(firmware), version, message)
    index = protect_body(index, firmware)
    print("Number of frames:", protect_end(index) + 1)


def start_protect(size: int, version: int, message: str):
    """
    Start message creation and encryption
    its just bytes that we put at the beginning of fw_protected
    
    First 4 byte: type (0x04)
    Next 4 bytes: version number
    Next 4 bytes: size (0x04)
    Next 4 bytes: Release message size
    Next 464 bytes: Release message

    for last frame:
    last 463 bytes: 
    """


    msg = bytearray(message.encode('utf-8'))

    metadata = []
    rmsize = len(msg)
    sizes = p32(0, endian='little') + p32(version, endian='little') + p32(size, endian='little') + p32(rmsize, endian='little')
    
    index = 0

    #-----------------------------------------WRITE MESSAGE INTO METADATA
    while index < len(msg):
        if (len(msg) - index) < RMmax:
            # Pad the data if there is less than RMmax bytes left of plaintxt
            plaintext = pad(sizes + msg[index:], 480, style='iso7816')
            metadata.append(plaintext)

        else:
            # Add RMmax bytes of plaintext
            metadata.append(sizes + msg[index:index + RMmax])

        index += RMmax
    #----------------------ENCRYPTION----------------------------------
    with open("../secret_build_output.txt", "rb") as keyfile:
        key = keyfile.read(16)
    outputMsg = []

    j = 0
    for i in metadata:
        header = p16(j)
        data = i

        cipher = AES.new(key, AES.MODE_GCM)

        cipher.update(header)

        #encrypt data
        ciphertext, tag = cipher.encrypt_and_digest(data)
        iv = cipher.nonce
        outputMsg.append((iv,tag,ciphertext))
        j = j + 1
    
    #--------------------------------------------Write ciphertext to protected_output
    with open("protected_output.bin", "wb") as f:
        for i in outputMsg:
            iv, tag, ciphertext = i
            f.write(iv + tag + ciphertext)

    return ceildiv(len(msg),RMmax)


def protect_body(frame_index: int, data: bytes):
    """
    Protects 32 bytes of data by encrypting it with AES-GCM using a key and AAD from a file.

    Returns: a frame containing the frame type, IV, encrypted data, tag, and padding
    """

    # This is to hold all the frames
    body = bytearray(0)

    with open("../secret_build_output.txt", "rb") as keyfile:
        key = keyfile.read(16)

    index = 0
    while index < len(data):
        # Create the frame buffer
        frame = bytearray(512)

        # Create the IV / nonce
        iv = get_random_bytes(16)
        frame[0:16] = iv

        ### Creating plaintext
        # Adding frame type code
        plaintext = bytearray(0)
        plaintext += p32(1, endian='little')
        # Adding firmware plaintext
        if len(data) - index < DATAmax:
            # Pad the data if there is less than DATAmax bytes left of plaintxt
            plaintext += data[index:]
            plaintext = pad(plaintext, 480, style='iso7816')    
        else:
            # Add DATAmax bytes of plaintext
            plaintext += data[index:index + DATAmax]

        index += DATAmax

        # Encrypt the data
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
        cipher.update(p16(frame_index))
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Add the tag to the frame
        frame[16:32] = tag

        # Add the ciphertext to the frame
        frame[32:] = ciphertext

        # Add the frame to the body
        body += frame

        # Adding one frame to the total number of them
        frame_index += 1

    # Putting all the data frames in the protected output thing
    with open("protected_output.bin", "ab") as f:
        f.write(body)

    # Return the entire protected firmware
    return frame_index

def protect_end(frame_index):
    with open("../secret_build_output.txt", "rb") as keyfile:
        key = keyfile.read(16)

    # Encrypting the end frame and padding it
    data = pad(p8(2, endian='little'), 480, style='iso7816')
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(p16(frame_index))

    #--------------------------------------------encrypt data
    ciphertext, tag = cipher.encrypt_and_digest(data)
    iv = cipher.nonce
    
    #--------------------------------------------Write ciphertext to protected_output
    with open("protected_output.bin", "ab") as f:
        f.write(iv + tag + ciphertext)

    return frame_index

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    # parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, version=int(args.version), message=args.message)
    # protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
