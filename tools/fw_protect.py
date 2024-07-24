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

def ceildiv(a, b):
    return -(a // -b)

def start_protect(total_size: int, version: int, message: str):
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

    msg = message.encode('ascii')
    metadata = []
    rmsize = len(message)

    if (len(msg) > 470):
        for i in range(0, (ceildiv(len(msg),471)-1)*471, 471):
            metadata.append(p8(1, endian='little') + p16(version, endian='little') + p64(size, endian='little') + p16(rmsize, endian='little') + pack(msg, word_size=471, endianness='little'))
        metadata.append(pad(p8(1, endian='little') + p16(version, endian='little') + p64(size, endian='little') + p16(rmsize, endian='little') + pack(msg[(ceildiv(len(msg),471)-1)*471:], word_size=470, endianness='little')), 480, style='iso7816')
    else:
        metadata.append(pad(p8(1, endian='little') + p16(version, endian='little') + p64(size, endian='little') + p16(rmsize, endian='little') + pack(msg, word_size=470, endianness='little')), 480, style='iso7816')

    
    #----------------------ENCRYPTION----------------------------------
    #------------------------TODO: implement header to import key
    #with open(keyfile, "rb") as key:
    key = get_random_bytes(16)

    # header = b"header"

    data = metadata[i]

    cipher = AES.new(key, AES.MODE_GCM)

    # cipher.update(header)

    #encrypt data
    ciphertext, tag = cipher.encrypt_and_digest(data)

    #store everything in json file
    # json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_k = ['nonce', 'ciphertext', 'tag']
    # json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, ciphertext, tag) ]
    outputMsg = json.dumps(dict(zip(json_k, json_v)))
    print(outputMsg)

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

def protect_32_bytes(data):
    """
    Protects 32 bytes of data by encrypting it with AES-GCM using a key and AAD from a file.

    Returns: a frame containing the frame type, IV, encrypted data, tag, and padding
    """

    with open("../secret_build_output.txt", "rb") as keyfile:
        key = keyfile.read(16)
        aad = keyfile.read(16)

    # If the data is empty, return an empty byte array
    if data is None:
        return bytearray(0)
    # Pad the data to be a multiple of 16 byets
    elif data % 32 != 0:
        data = pad(data, 16)

    # Create the frame buffer
    frame = bytearray(len(data) + 1 + 16 + 32 + 16)
    byte_ind = 0
    frame[byte_ind] = 0x01
    byte_ind += 1

    # Create the IV / nonce
    iv = get_random_bytes(16)
    frame[byte_ind:byte_ind+16] = iv
    byte_ind += 16

    # Encrypt the data
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    cipher.add(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    frame[byte_ind:byte_ind+32] = ciphertext
    byte_ind += 32
    frame[byte_ind:byte_ind+16] = tag

    # Padding the rest of the frame to a multiple of 16
    frame = pad(frame, 16)

    # Return the key and the encrypted data
    return frame

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--totalsize", help="Total size of all data chunks (total firmware size)", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    start_protect(total_size=int(args.totalsize), version=int(args.version), message=args.message)

    # parser = argparse.ArgumentParser(description="Firmware Update Tool")
    # parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    # parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    # parser.add_argument("--version", help="Version number of this firmware.", required=True)
    # parser.add_argument("--message", help="Release message for this firmware.", required=True)
    # args = parser.parse_args()

    # protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
