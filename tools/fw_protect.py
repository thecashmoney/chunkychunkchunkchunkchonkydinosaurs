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
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def start_protect(startMsg, outputMsg, version, message):
    # Load start binary from infile
    with open(startMsg, "rb") as fp:
        start = fp.read()

    
    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message



    #----------------------ENCRYPTION----------------------------------

    #with open(keyfile, "rb") as key:
    key = b""


    header = b"header"

    data = version + int.to_bytes(len(version)) + message
    key = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_GCM)

    cipher.update(header)

    ciphertext, tag = cipher.encrypt_and_digest(data)


    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]

    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]

    result = json.dumps(dict(zip(json_k, json_v)))

    #--------------------------------------------------------------

    
    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        outfile.write(firmware_blob)

def protect_firmware(infile, outfile, version, message):

    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()


    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message



    #----------------------ENCRYPTION----------------------------------

    #with open(keyfile, "rb") as key:
    key = b""


    cipher = AES.new(key, 11)

    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(firmware_blob)

    #--------------------------------------------------------------

    
    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        outfile.write(firmware_blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)