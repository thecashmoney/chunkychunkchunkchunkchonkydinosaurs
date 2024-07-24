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


def start_protect(version, message, outputMsg):
    """
    Start message creation and encryption
    its just bytes that we put at the beginning of fw_protected

    First 1 byte: type (0x00)
    Next 2 bytes: size (0x02)
    Next 16 bytes: IV
    Next 2 bytes: reease message size
    Next x bytes: ciphertext with version number
    Last 10 bytes: tag
    """

    metadata = p16(version, endian='little') + p16(message, endian='little') 

    #----------------------ENCRYPTION----------------------------------
    #------------------------TODO: implement header to import key
    #with open(keyfile, "rb") as key:
    key = get_random_bytes(16)

    header = b"header"

    data = metadata

    cipher = AES.new(key, AES.MODE_GCM)

    cipher.update(header)

    #encrypt data
    ciphertext, tag = cipher.encrypt_and_digest(data)

    #store everything in json file
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    outputMsg = json.dumps(dict(zip(json_k, json_v)))

    #--------------------------------------------------------------

    #---------------------------------- i dont think i need this but keeping it just in case
    # # Write firmware blob to outfile
    # with open(outfile, "wb+") as outfile:
    #     outfile.write(firmware_blob)

def protect_firmware(infile, outfile, version, message):

    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()


    # Append null-terminated message to end of firmware
    firmmware_and_message = firmware + message.encode() + b"\00"

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

def protect_body(data):
    """
    Protects 32 bytes of data by encrypting it with AES-GCM using a key and AAD from a file.

    Returns: a frame containing the frame type, IV, encrypted data, tag, and padding
    """
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
        plaintext += 0x02
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


        # Return the key and the encrypted data
        frame[16:] = plaintext
        index += 32


    # Return the key and the encrypted data
    return frame

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
