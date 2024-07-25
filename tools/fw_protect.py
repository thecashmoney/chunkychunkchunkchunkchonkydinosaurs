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

def ceildiv(a, b):
    return -(a // -b)

def start_protect(size: int, version: int, message: str):
    """
    Start message creation and encryption
    its just bytes that we put at the beginning of fw_protected
    
    First 1 byte: type (0x01)
    Next 2 bytes: version number
    Next 4 bytes: size (0x04)
    Next 2 bytes: Release message size
    Next 471 bytes: Release message

    for last frame:
    last 470 bytes: 
    """

    msg = bytearray(message.encode('ascii'))

    metadata = []
    rmsize = len(msg)

    if (len(msg) > 470):
        for i in range(0, (ceildiv(len(msg),471)-1)*471, 471):
            metadata.append(p8(0, endian='little') + p16(version, endian='little') + p32(size, endian='little') + p16(rmsize, endian='little') + msg[i:i+471])
        metadata.append(pad((p8(0, endian='little') + p16(version, endian='little') + p32(size, endian='little') + p16(rmsize, endian='little') + msg[(ceildiv(len(msg),471)-1)*471:]), block_size=480, style='iso7816'))
    else:
        metadata.append(pad((p8(0, endian='little') + p16(version, endian='little') + p32(size, endian='little') + p16(rmsize, endian='little') + msg), block_size=480, style='iso7816'))

    
    #----------------------ENCRYPTION----------------------------------
    with open("../secret_build_output.txt", "rb") as keyfile:
        key = keyfile.read(16)
    outputMsg = []

    #header = b"header"
    for i in metadata:
        data = i

        cipher = AES.new(key, AES.MODE_GCM)

        #cipher.update(header)

        #encrypt data
        ciphertext, tag = cipher.encrypt_and_digest(data)
        iv = cipher.nonce
        outputMsg.append((iv,tag,ciphertext))
    
    #--------------------------------------------Write ciphertext to protected_output
    with open("protected_output.bin", "wb") as f:
        for i in outputMsg:
            iv, tag, ciphertext = i
            f.write(iv + tag + ciphertext)

    return


def protect_firmware(infile, version, message):

    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    start_protect(len(firmware), version, message)
    protect_body(firmware)
    

def protect_body(data):
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
        plaintext += b'\x01'
        # Adding firmware plaintext
        if len(data) - index < (480 - len(plaintext)):
            # Pad the data if there is less than 479 bytes left of plaintxt
            plaintext += data[index:]
            plaintext = pad(plaintext, 480, style='iso7816')
        else:
            # Add 479 bytes of plaintext
            plaintext += data[index:index + 479]

        index += 479

        # Encrypt the data
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Add the tag to the frame
        frame[16:32] = tag

        # Add the ciphertext to the frame
        frame[32:] = ciphertext

        # Add the frame to the body
        body += frame

    # Putting all the data frames in the protected output thing
    with open("protected_output.bin", "ab") as f:
        f.write(body)

    # Return the entire protected firmware
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    # parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, version=int(args.version), message=args.message)
    # protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
