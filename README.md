![5xCD cover page](https://github.com/thecashmoney/chunkychunkchunkchunkchonkydinosaurs/blob/main/5xcdREADME.png?raw=true)


# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)

CrASHBoot is a secure automotive bootloader designed to ensure the safe updating and protection of your vehicle's firmware. This guide provides a detailed overview of how to install, build, and use CrASHBoot to manage your vehicle's firmware securely.

# Overview

CrASHBoot consists of three main components:

1. Bootloader: Manages firmware updates and ensures only authorized firmware is installed.
2. Tools: Scripts for building the bootloader, protecting the firmware, and updating the firmware.

## How to Use

1. Build the Bootloader: Run bl_build.py to generate encryption keys and build the bootloader.
2. Protect the Firmware: Run fw_protect.py with the required parameters to encrypt the firmware.
3. Flash the Bootloader: Use lm4flash to flash the bootloader onto the microcontroller.
3. Update the Firmware: Run fw_update.py to flash the protected firmware using the bootloader.
4. Interact with the Bootloader: Use car-serial to boot the new firmware.
Project Structure

```
├── bootloader *
│   ├── bin
│   │   ├── bootloader.bin
│   ├── src
│   │   ├── bootloader.c
│   │   ├── startup_gcc.c
│   ├── bootloader.ld
│   ├── Makefile
├── firmware
│   ├── bin
│   │   ├── firmware.bin
│   ├── lib
│   ├── src
├── lib
│   ├── driverlib
│   ├── inc
│   ├── uart
├── tools *
│   ├── bl_build.py
│   ├── fw_protect.py
│   ├── fw_update.py
│   ├── util.py
├── README.md
```
Directories marked with * are part of the CrASHBoot system.

## Bootloader

The bootloader directory contains source code for the TM4C microcontroller. The bootloader checks the version of new firmware and ensures secure updates.

## Tools

### bl_build.py
Generates a random 16-byte encryption key, writes it to secrets.h, and builds the bootloader.

#### Usage:

```bash
$ python3 bl_build.py
```

### fw_protect.py

Encrypts the firmware using AES-GCM with a frame counter as additional authenticated data (AAD). The frame counter starts at 0 and increments with each frame.

#### Parameters:

* `--infile`: Path to the input firmware file.
* `--outfile`: Path to the output encrypted firmware file.
* `--version`: Firmware version.
* `--message`: Firmware release message.

```bash
python3 fw_protect.py --infile firmware.bin --outfile firmware_protected.bin --version 1 --message "Firmware :("
```

### fw_update.py
Sends the encrypted firmware to the bootloader in 512-byte frames, waiting for an acknowledgment (OK) from the bootloader after each frame.

Usage:

```bash
python3 fw_update.py --infile firmware_protected.bin
```
## Step-by-Step Guide

1. Building and Flashing the Bootloader
Navigate to the tools directory and run bl_build.py:
```sh
cd ./tools
python3 bl_build.py
```

2. Flash the bootloader using lm4flash:
sh
Copy code
```sh
sudo lm4flash ../bootloader/bin/bootloader.bin
```
2. Bundling and Updating Firmware
Navigate to the firmware directory and build the example firmware:
```sh
cd ./firmware
make
```

3. Protect the firmware:
```sh
cd ../tools
python3 fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Firmware V2"
```
4. Reset the TM4C by pressing the RESET button.


5. Update the firmware:
```sh
python3 fw_update.py --firmware ./firmware_protected.bin
```
6. Interacting with the Bootloader
Using the custom car-serial script:

```sh
car-serial
```

Exit picocom: Ctrl-A X

## Launching the Debugger
Use OpenOCD with the configuration files for the board to get it into debug mode and open GDB server ports:

```sh
openocd -f /usr/share/openocd/scripts/interface/ti-icdi.cfg -f /usr/share/openocd/scripts/board/ti_ek-tm4c123gxl.cfg
```
Start GDB and connect to the main OpenOCD debug port:

```sh
gdb-multiarch -ex "target extended-remote localhost:3333" bootloader/bin/bootloader.axf
```
Go to main function and set a breakpoint:

```gdb
layout src
list main
break bootloader.c:50
```
By following these steps, you can securely manage and update your vehicle's firmware using CrASHBoot.

Note: This README assumes you have all necessary tools and dependencies installed and configured correctly.