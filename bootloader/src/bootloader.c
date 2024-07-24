// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.


//NOTE: UNTESTED CODE, BUT PUSHING TO BOOTLOADER_DECRYPT SO THAT I CAN START WORKING ON MESSAGE DECRYPTION

/*
TODO:
- add the thing that jayden said to add (i lowk forgot it uhmmmmmm trust tho)
- add decryption (bootloader_decrypt) - check it probably doesnt work but lets goooo
- change the value of index to actually be at the correct index 
- find out how to obtain the key from the secrets.h
- implement the check version function
- 
- add verification of packets (bootloader_verify)
- add functions that prevent debugging in gdb
*/

#include "bootloader.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // Turn on the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

    // Wait
    SysCtlDelay(SysCtlClockGet() * 2);

    // Turn off the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}

int main(void) {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}



void unpad(uint8_t[] plaintext, uint8_t unpadded_plaintext[]) {
    int index;
    for(int i = 479; i >= 0; i--) {
        if(plaintext[i] == 0x80) 
            index = i;
    }

    for(int i = 0; i < index; i++) {
        unpadded_plaintext[i] = plaintext[i];
    }
}

 /*
 * Load the firmware into flash.
 */


uint8_t[] read_start_packet(uint8_t plaintext[480]){
    uint8_t IV[16];
    uint8_t tag[16];
    uint8_t ciphertext[480];
    Aes decrypt;
    uint8_t authTag[16];

    //auth tag length = 16 (?)

    for(int i = 0; i < 16; i++) {
        rcv = uart_read(UART0, BLOCKING, &resp);
        IV[i] = (uint8_t) rcv;
        printf("%d ", IV[i]);
        //printing for testing purposes
    }

    printf("\n");

    for(int i = 0; i <16; i++) {
        rcv = uart_read(UARTO, BLOCKING, &resp);
        tag[i] = (uint8_t) rcv;
        printf("%d ", tag[i])
    }

    printf("\n");

    for(int i = 0; i < 480; i++) {
        rcv = uart_read(UARTO, BLOCKING, &resp);
        ciphertext[i] = (uint8_t)rcv;
        printf("%d", ciphertext[i]);
    }

    printf("\n");

    wc_AesGcmSetKey(decrypt, key, sizeof(key));	
    wc_AesGcmDecrypt(&enc, plaintext, ciphertext, sizeof(ciphertext), IV, sizeof(IV), authTag, sizeof(authTag), tag, sizeof(tag));

    uint16_t version;

    first_half = plaintext[1];
    second_half = plaintext[2];
    first_half = first_half << 8;
    version = first_half |= second_half;

    check_version(version); //NOT GOING TO IMPLEMENT THIS RN BC IM COPING BUT ITS SUPPOSED TO CHECK THE VERSION AND SEND PACKET BASED ON THIS

    return plaintext;

}
void load_firmware(void) {
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint8_t IV[16];
    uint8_t tag[16]
    uint32_t size = 0;
    Aes decrypt;
    uint8_t ciphertext[480];
    final uint32_t CTEXT_SIZE = 480;
    uint8_t plaintext[480];
    uint8_t authTag[16];
    uint8_t type;
    uint16_t version;
    uint16_t rel_msg_size;
    uint8_t max_frames;
    uint8_t current_frame = 0;
    
    //auth tag length = 16 (?)

    for(int i = 0; i < 16; i++) {
        rcv = uart_read(UART0, BLOCKING, &resp);
        IV[i] = (uint8_t) rcv;
        printf("%d ", IV[i]);
        //printing for testing purposes
    }

    printf("\n");

    for(int i = 0; i <16; i++) {
        rcv = uart_read(UARTO, BLOCKING, &resp);
        tag[i] = (uint8_t) rcv;
        printf("%d ", tag[i])
    }

    printf("\n");

    for(int i = 0; i < 480; i++) {
        rcv = uart_read(UARTO, BLOCKING, &resp);
        ciphertext[i] = (uint8_t)rcv;
        printf("%d", ciphertext[i]);
    }

    printf("\n");

   wc_AesGcmSetKey(decrypt, key, sizeof(key));	
    wc_AesGcmDecrypt(&enc, plaintext, ciphertext, sizeof(ciphertext), IV, sizeof(IV), authTag, sizeof(authTag), tag, sizeof(tag));
    for(int i = 0; i < sizeof(plaintext); i++) {
        printf("%c", plaintext[i]);
    }

    type = plaintext[0];
    metadata = malloc(sizeof(uint8_t) * 480); /* allocate memory for 480 bytes's */
    if (!metadata) { /* If data == 0 after the call to malloc, allocation failed for some reason */
        perror("Error allocating memory");
        abort();
    }
  /* at this point, we know that data points to a valid block of memory.
     Remember, however, that this memory is not initialized in any way -- it contains garbage.
     Let's start by clearing it. */

    memset(metadata, 0, sizeof(uint8_t)*datacount);
    if(type == 0) {
        first_half = plaintext[1];
        second_half = plaintext[2];
        first_half = first_half << 8;
        version = first_half |= second_half;

        size = plaintext[3] << 24 |= plaintext[4] << 16 | plaintext[5] << 8 | plaintext[6];
        rel_msg_size = plaintext[7] << 8 |= plaintext[8];
        if(rel_msg_size % 470 == 0) {
            max_frames = rel_msg_size / 470;
        } else {
            max_frames = (rel_msg_size / 470) + 1
        }
        metadata = realloc(metadata, sizeof(uint8_t) * rel_msg_size);
        int index = 0;
        //index is not 0 please change this to what the actual index of the release message is (i cant do math rn)
        
        while(current_frame != max_frames) {
            for(int i = index; i < sizeof(plaintext); i++) {
                metadata[index] = plaintext[i];
                index++;
            }
            plaintext = read_packet(plaintext);
            //this is so scuffed im crying bru
        }

        uint8_t unpadded_plaintext[480];
        unpad(plaintext, unpadded_plaintext);
        for(int i = 0; i < sizeof(metadata); i++) {
            metadata[i] = unpadded_plaintext[i]
        }
        //testing metadata

        for(int i = 0; i < sizeof(metadata); i++) {
            printf("%c", metadata[i]);
        }
    }


    //original starter code: keeping for reference cuz i lowk dk what im doing lmao
    // // Get version.
    // rcv = uart_read(UART0, BLOCKING, &read);
    // version = (uint32_t)rcv;
    // rcv = uart_read(UART0, BLOCKING, &read);
    // version |= (uint32_t)rcv << 8;

    // // Get size.
    // rcv = uart_read(UART0, BLOCKING, &read);
    // size = (uint32_t)rcv;
    // rcv = uart_read(UART0, BLOCKING, &read);
    // size |= (uint32_t)rcv << 8;


    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART0, OK); // Acknowledge the metadata.

    /* Loop here until you can get all your characters and stuff */
    while (1) {

        // Get two bytes for the length.
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length += (int)rcv;

        // Get the number of bytes specified
        for (int i = 0; i < frame_length; ++i) {
            data[data_index] = uart_read(UART0, BLOCKING, &read);
            data_index += 1;
        } // for

        // If we filed our page buffer, program it
        if (data_index == FLASH_PAGESIZE || frame_length == 0) {
            // Try to write flash and check for error
            if (program_flash((uint8_t *) page_addr, data, data_index)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // If at end of firmware, go to main
            if (frame_length == 0) {
                uart_write(UART0, OK);
                break;
            }
        } // if

        uart_write(UART0, OK); // Acknowledge the frame.
    } // while(1)
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
}

void boot_firmware(void) {
    // Check if firmware loaded
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset();            // Reset device
        return;
    }

    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART0, (char *)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}
