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
        for i in range(0, len(out) // 512):
            frames.append(out[i * 512: (i + 1) * 512])
        print("Received ", len(frames), " frames.")

    with open("../secret_build_output.txt", "rb") as keyfile:
        key = keyfile.read(16)

    size, index = unprotect_start(frames, key)
    index = unprotect_body(frames, key, index, size)
    unprotect_end(frames, key, index)








def printStart_noPad(i:bytes, key:bytes, aad:int):
    # Same for all the frames
    iv = i[:16]
    tag = i[16:32]
    ciphertext = i[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(p16(aad))
    # Getting plaintext with data and metadata
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    print("Msg type: ", u32(plaintext[:4]))
    print("Version number: ", u32(plaintext[4:8]))
    print("Total size: ", u32(plaintext[8:12]))
    print("Release msg size: ", u32(plaintext[12:16]))
    print("Release msg: ", plaintext[16:])

def printStart_Pad(i:bytes, key:bytes, aad:int):
    iv = i[:16]
    tag = i[16:32]
    ciphertext = i[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(p16(aad))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    pt = unpad(plaintext, block_size=480, style='iso7816')


    print("Msg type: ", u32(pt[:4]))
    print("Version number: ", u32(pt[4:8]))
    print("Total size: ", u32(pt[8:12]))
    print("Release msg size: ", u32(pt[12:16]))
    print("Release msg: ", pt[16:])






def unprotect_start(frames, key):#------------------------------------UNPROTECT START
    #--------------------------------------------GET FIRST CHONK TO GET LENGTH
    firstChonk = frames[0]
    iv = firstChonk[:16]
    tag = firstChonk[16:32]
    ciphertext = firstChonk[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(p16(0))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    padLastChonk = True
    
    rmsize = u32(plaintext[12:16])
    if rmsize % 464 != 0:
        numFrames = (rmsize // 464) + 1
    else:
        numFrames = (rmsize // 464)
        padLastChonk = False

    #------------------------------------------GET MIDDLE CHONKS
    for x in range(numFrames-1):
        i = frames[x]
        printStart_noPad(i, key, x)

    #-----------------------------------------------GET LAST CHONK
    if(padLastChonk):
        printStart_Pad(frames[numFrames-1], key, numFrames-1)

    else:
        printStart_noPad(frames[numFrames-1], key, numFrames-1)

    return((u32(plaintext[8:12]), numFrames))
    
    

def unprotect_body(frames, key, index, size):
    complete_firmware = b''
    for x in range(0, size // 464):
        current = frames[index]

        # Same for all the frames
        iv = current[:16]
        tag = current[16:32]
        ciphertext = current[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(p16(index))
        
        try:
            # Getting plaintext with data and metadata
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError) as e:
            print(e)
            return

        mType = u8(plaintext[:1])
        
        if mType != 1:
            print("Message type error. Supposed to be 1 but is", mType)
        else:
            print("Msg type: ", mType)
        
        print("Firmware frame:", plaintext[1:])

        complete_firmware += plaintext[1:]

        index += 1
    
    # No padded chunk
    if size % 464 == 0:
        print(len(complete_firmware))
        return index

    #---------------------------Getting last padded chunk if exists
    current = frames[index]

    # Same for all the frames
    iv = current[:16]
    tag = current[16:32]
    ciphertext = current[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(p16(index))
    
    try:
        # Getting plaintext with data and metadata
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), 480, style="iso7816")
    except (ValueError, KeyError) as e:
        print(e)
        return

    mType = u8(plaintext[:1])
    
    if mType != 1:
        print("Message type error. Supposed to be 1 but is", mType)
    else:
        print("Msg type: ", mType)
    
    print("Firmware frame:", plaintext[1:])

    complete_firmware += plaintext[1:]

    index += 1

    # Returning the length of the complete firmware
    print("Length of firmare according to file:", size, "\nLength of firmware according to us:", len(complete_firmware))
    
    return index

def unprotect_end(frames, key, index):
    chonk = frames[index]
    iv = chonk[:16]
    tag = chonk[16:32]
    ciphertext = chonk[32:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(p16(index))

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    plaintext = u8(unpad(plaintext, 480, style="iso7816"))
    if(plaintext == 2):
        print("END MESSAGE REACHED")
        print("Msg type: ", plaintext)
    else:
        print("Frame error")

if __name__ == "__main__":
    main()











