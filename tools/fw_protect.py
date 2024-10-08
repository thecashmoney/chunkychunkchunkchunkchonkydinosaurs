#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

7/22/24 - Elliott Jang and Oliver Beresford
Part 1: Start message encryption
- start_protect(size (int), version (int), message(str))
- Finds length of message, and calculates number of frames required
- Adds in required data headers (look at function for more info)
- Add in release message in increments of 464 bytes
- Encrypt whole chonk, using a frame number as the AAD
- Write every chonk to protected_output.bin
- Return frame number that next part should start off of

Part 2: Data message encryption: 
- Read over GCM key, index
- Split into chonks first and then encrypt each chonk
- Each data is 476 bytes
- 4 bytes of message code
- Continue to use frame counter for AAD
- Return next frame number

Part 3: End message encryption
- Read and stores the AES-GCM key
- Pads the end frame with ISO-7816
- Encrypts the end frame
- Writes the ciphertext to protected_output
"""

import argparse
from pwn import *
from Crypto.Util.Padding import pad, unpad
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# Setting constants for easy packet redesign
RMmax = 464  # Release msg maximum size
DATAmax = 476  # Data msg maximum size


# Defines a function for ceiling division (always round up)
def ceildiv(a, b):
    return -(a // -b)

# This is the "main" function
def protect_firmware(infile, version, message, outfile):

    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()
    # calls start_protect to protect the start message frames
    index = start_protect(len(firmware), version, message, outfile)
    
    # calls protect_body to protect the data message frames
    index = protect_body(index, firmware, outfile)

    # calls protect_end to protect the end message frames
    protect_end(index, outfile)
    #print("Number of frames:", protect_end(index) + 1)


# Protects the start message
def start_protect(size: int, version: int, message: str, outfile):
    """
    Start message creation and encryption
    
    First 4 byte: type (0x04)
    Next 4 bytes: version number
    Next 4 bytes: size (0x04)
    Next 4 bytes: Release message size
    Next 464 bytes: Release message

    for last frame:
    ...
    last 463 bytes: Release message
    Padded with ISO-7816
    """

    # Turns message into a bytearray and stores it in msgn
    msg = bytearray(message.encode('utf-8'))


    metadata = []  # stores start_message metadata
    rmsize = len(msg)  # stores the release msg size

    # msg type, version number, data size, release msg size
    sizes = p32(1, endian='little') + p32(version, endian='little') + p32(size, endian='little') + p32(rmsize, endian='little')
    
    index = 0

    # -------------------------------- WRITE MESSAGE INTO METADATA -------------------------------- #
    while index < len(msg):
        if (len(msg) - index) < RMmax:
            # Pad the data if there is less than RMmax bytes left of plaintxt
            plaintext = pad(sizes + msg[index:], 480, style='iso7816')
            metadata.append(plaintext)

        else:
            # Add RMmax bytes of plaintext
            metadata.append(sizes + msg[index:index + RMmax])

        index += RMmax
    # -------------------------------- END -------------------------------- #


    # -------------------------------- ENCRYPTION -------------------------------- #
    with open("../secret_build_output.txt", "r") as keyfile:
        key = bytearray([ord(c) for c in keyfile.read(16)])
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
    # -------------------------------- END -------------------------------- #

    
    # -------------------------------- WRITE CIPHERTEXT TO protected_output -------------------------------- #
    with open(outfile, "wb") as f:
        for i in outputMsg:
            iv, tag, ciphertext = i
            f.write(iv + tag + ciphertext)

    return ceildiv(len(msg),RMmax)
    # -------------------------------- END -------------------------------- #


# Protects the data msg frames 
def protect_body(frame_index: int, data: bytes, outfile):
    """
    Body message creation and encryption
    
    First 4 byte: type (0x04)
    Next 476 bytes: Data
    Padded with ISO-7816
    """

    # This is to hold all the frames
    body = bytearray(0)

    # Reads the file containing the AES-GCM key
    with open("../secret_build_output.txt", "r") as keyfile:
        key = bytearray([ord(c) for c in keyfile.read(16)])

    index = 0
    
    # This while loop encrypts each 32 byte chunk of data
    while index < len(data):
        # Create the frame buffer
        frame = bytearray(512)

        # Create the IV / nonce
        iv = get_random_bytes(16)
        frame[0:16] = iv

        ### Creating plaintext
        # Adding frame type code
        plaintext = bytearray(0)
        plaintext += p32(2, endian='little')

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
    with open(outfile, "ab") as f:
        f.write(body)

    # Return the entire protected firmware
    return frame_index


# Protects the end_msg frames
def protect_end(frame_index, outfile):
    """
    End message creation and encryption
    
    First 4 byte: type (0x04)
    Padded with ISO-7816
    """
    
    # Opens the AES-GCM key
    with open("../secret_build_output.txt", "r") as keyfile:
        key = bytearray([ord(c) for c in keyfile.read(16)])

    # Encrypting the end frame and padding it
    data = pad(p32(3, endian='little'), 480, style='iso7816')
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(p16(frame_index))

    # -------------------------------- ENCRYPT DATA -------------------------------- #
    ciphertext, tag = cipher.encrypt_and_digest(data)
    iv = cipher.nonce
    # -------------------------------- END -------------------------------- #
    
    # -------------------------------- WRITE CIPHERTEXT TO protected_output -------------------------------- #
    with open(outfile, "ab") as f:
        f.write(iv + tag + ciphertext)
    # -------------------------------- END -------------------------------- #
    
    return frame_index

if __name__ == "__main__":
    # -------------------------------- OG (Template) Code -------------------------------- #
    parser = argparse.ArgumentParser(description="Firmware Protection Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    parser.add_argument("--outfile", help="File for the output of this program.", required=True)
    
    args = parser.parse_args()
    # -------------------------------- END -------------------------------- #
    
    
    # Calls protect_firmware function
    protect_firmware(infile=args.infile, version=int(args.version), message=args.message, outfile=args.outfile)