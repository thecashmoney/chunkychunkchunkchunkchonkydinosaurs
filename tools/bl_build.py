#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.

It generates an AAD and a AES-GCM 128 bit cipher and stores them in secrets.h
"""


import os
import pathlib
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

# Function to update a given headerfile
def update_line(headerFile, varUpdate, value):
    # Expand environment variables in the file path
    headerFile = os.path.expandvars(headerFile)

    # Read the existing content of the header file
    with open(headerFile, 'r') as file:
        lines = file.readlines()

    # define pattern and newMsg
    pattern = f'define {varUpdate}'  # defines the pattern to look for
    newMsg = f'#define {varUpdate} 0x{value}\n'  # defines the new msg that will be input into the file
    
    # Update the line with the new value
    for i, line in enumerate(lines):
        if pattern in line:
            lines[i] = newMsg
            break
    else:
        # If the variable was not found, add it to the end of the file
        lines[-1] = newMsg
        lines.append('\n#endif')

    # Write the updated content back to the header file
    with open(headerFile, 'w') as file:
        file.writelines(lines)


# Function to generate the keys and build the bootloader
def make_bootloader() -> bool:
    # Generate AAD (Additional Authentication Data)
    aad = get_random_bytes(16)  # used to authenticate integrity of the encrypted data

    # Generate AES-GCM (128 bit) key
    aesKey = get_random_bytes(16)


    # update secrets.h with the newly generated AES-GCM (128 bit) key
    update_line("${HOME}/chunkychunkchunkchunkchonkydinosaurs/bootloader/inc/secrets.h", "aesKey", aesKey.hex())

    # update secrets.h with the newly generated AAD 
    update_line("${HOME}/chunkychunkchunkchunkchonkydinosaurs/bootloader/inc/secrets.h", "aad", aad.hex())


    # --------------------- DO NOT TOUCH THIS CODE ---------------------
    # Build the bootloader from source.

    '''os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0'''

    # --------------------- END OF UNTOUCHABLE CODE ---------------------


if __name__ == "__main__":
    make_bootloader()