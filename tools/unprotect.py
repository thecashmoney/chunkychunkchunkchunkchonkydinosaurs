import argparse
from pwn import *
from Crypto.Util.Padding import pad, unpad
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

#-----------------------------------------------DECRYPT FUNCTION
#------------------NOTE: USE THIS FOR DECRYPTION, ITS WORKS GREAT

def main():
    with open("protected_output.bin", "rb") as f:
        out = f.read()

        # Converting the files into the separate frames
        frames = []
        if len(out) % 512 != 0:
            print("Error with firmware file")
            return
        for i in range(0, len(out) // 512, 512):
            frames.append(out[i * 512: (i + 1) * 512])
        
        print(frames)

    with open("../secret_build_output.txt", "rb") as keyfile:
        key = keyfile.read(16)

    size, index = unprotect_start(frames, key)
    unprotect_body(frames, key, index, size)


def unprotect_start(frames, key):#------------------------------------UNPROTECT START
    #--------------------------------------------GET FIRST CHONK
    firstChonk = frames[0]
    iv = firstChonk[:16]
    tag = firstChonk[16:32]
    ciphertext = firstChonk[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    pt = unpad(plaintext, block_size=480, style='iso7816')
    
    rmsize = u16(pt[7:9])
    numFrames = (rmsize // 470) + 1

    #------------------------------------------GET MIDDLE CHONKS
    for x in range(numFrames-1):
        i = frames[x]

        # Same for all the frames
        iv = i[:16]
        tag = i[16:32]
        ciphertext = i[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        # Getting plaintext with data and metadata
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        print("Msg type: ", u8(plaintext[0]))
        print("Version number: ", u16(plaintext[1:3]))
        print("Total size: ", u32(plaintext[3:7]))
        print("Release msg size: ", u16(plaintext[7:9]))
        print("Release msg: ", plaintext[9:480])

    #-----------------------------------------------GET LAST CHONK
    lastChonk = frames[numFrames-1]
    iv = lastChonk[:16]
    tag = lastChonk[16:32]
    ciphertext = lastChonk[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    pt = unpad(plaintext, block_size=480, style='iso7816')


    print("Msg type: ", u8(pt[:1]))
    print("Version number: ", u16(pt[1:3]))
    print("Total size: ", u32(pt[3:7]))
    print("Release msg size: ", u16(pt[7:9]))
    print("Release msg: ", pt[9:])

    return((u32(pt[3:7]), numFrames))
    
    

def unprotect_body(frames, key, index, size):
    complete_firmware = b''
    for x in range(0, size // 471):
        current = frames[index]

        # Same for all the frames
        iv = current[:16]
        tag = current[16:32]
        ciphertext = current[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Getting plaintext with data and metadata
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        mType = u8(plaintext[0])
        
        if mType != 1:
            print("Message type error. Supposed to be 1 but is", mType)
        else:
            print("Msg type: ", mType)
        
        print("Firmware frame:", plaintext[1:])

        complete_firmware += plaintext[1:]

        index += 1
    
    # No padded chunk
    if size % 479 == 0:
        print(len(complete_firmware))
        return index

    #---------------------------Getting last padded chunk if exists
    current = frames[index]

    # Same for all the frames
    iv = current[:16]
    tag = current[16:32]
    ciphertext = current[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    # Getting plaintext with data and metadata
    plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), 480, style='iso7816')

    mType = u8(plaintext[0])
    
    if mType != 1:
        print("Message type error. Supposed to be 1 but is", mType)
    else:
        print("Msg type: ", mType)
    
    print("Firmware frame:", plaintext[1:])

    complete_firmware += plaintext[1:]

    index += 1

    # Returning the length of the complete firmware
    print("Length of firmare according to file:", size, "\nLength of firmware according to us", len(complete_firmware))
    
    return index

if __name__ == "__main__":
    main()