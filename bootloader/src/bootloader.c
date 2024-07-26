// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"
#include "../lib/wolfssl/wolfssl/wolfcrypt/error-crypt.h"
#include "../inc/secrets.h"

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
int decrypt(generic_frame *frame, uint16_t *frame_num, uint8_t *plaintext);

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


// Reads in the IV and the tag from fw_update.py
void receive_IV_tag(uint8_t *IV, uint8_t *tag)
{
    int read;
    uint32_t rcv;

    // Reads the IV
    for (int i=0; i<16; i++)
    {
        rcv = uart_read(UART0, BLOCKING, &read);
        IV[i] = (uint8_t) rcv;
    }

    // Reads the tag
    for (int i=0; i<16; i++)
    {
        rcv = uart_read(UART0, BLOCKING, &read);
        tag[i] = (uint8_t) rcv;
    }
}

// Reads in the IV and the tag from fw_update.py
void receive_ciphertext(uint8_t *ciphertext)
{
    int read;
    uint32_t rcv;

    // Reads the ciphertext
    for (int i=0; i<480; i++)
    {
        rcv = uart_read(UART0, BLOCKING, &read);
        ciphertext[i] = (uint8_t) rcv;
    }
}

/*
* Reads the packets sent by fw_update.py 
* Sends the ciphertext to decrypt_ciphertext()
*/
uint32_t read_frame(generic_frame *frame) 
{
    // read the IV and tag and store them in the generic_frame struct
    receive_IV_tag(frame->IV, frame->tag); 

    // read the ciphertext and store it in the generic_frame struct
    receive_ciphertext(frame->ciphertext);

    // send back a null byte 
    return OK;


    // // TODO: Remove the testing for loops later
    // for (int i=0; i<16; i++)
    // {
    //     uart_write(UART0, frame->IV[i]);
    // }    
    // for (int i=0; i<16; i++)
    // {
    //     uart_write(UART0, frame->tag[i]);
    // }
    // for (int i=0; i<480; i++)
    // {
    //     uart_write(UART0, frame->ciphertext[i]);
    // }
}


 /*
 * Load the firmware into flash.
 */
void load_firmware(void) {

    /* -------------------------------- This code if for the frist start frame -------------------------------- */
    // Actual variable for reading encrypted frames
    generic_frame frame_encrypted;
    generic_frame *frame_enc_ptr = &frame_encrypted;
    // Actual variable for storing decrypting frames
    generic_decrypted_frame frame_decrypted;
    generic_decrypted_frame *frame_dec_ptr = &frame_decrypted;
    // References to frame_decrypted, but can be read as if they were frame_dec_body / frame_dec_start / frame_dec_end
    pltxt_body_frame *frame_dec_body = (pltxt_body_frame *) frame_dec_ptr;
    pltxt_start_frame *frame_dec_start = (pltxt_start_frame *) frame_dec_ptr;
    pltxt_end_frame *frame_dec_end = (pltxt_end_frame *) frame_dec_ptr;

    uart_write(UART0, read_frame(frame_enc_ptr));

    uint32_t frame_ind = 0;
    uint32_t *frame_index = &frame_ind;
    // Decrypt the very first start frame
    decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext);

    // If the first frame is not 0, there is an error
    if (frame_dec_ptr->type != 0) {
        uart_write(UART0, ERROR);
        return;
    }

    // Saving the metadata
    uint32_t version = frame_dec_start->version_num;
    uint32_t fw_size = frame_dec_start->total_size;
    uint32_t msg_size = frame_dec_start->msg_size;

    // Making sure the old version isn't smaller than the current version
    uint16_t old_version = *fw_version_address;
    uint16_t old_size = *fw_size_address;
    if (old_version == 0xFFFF) {
        // Version not set
        old_version = version;
        old_size = fw_size;
    } else if (version < old_version) {
        // Attempted rollback
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    } else {
        // Update version
        old_version = version;
        old_size = fw_size;
    }

    /* -------------------------------- This code if for the next start frames -------------------------------- */

    if (msg_size > FRAME_MSG_LEN) {
        // Iterate through start frames
        uint32_t num_frames = msg_size % FRAME_MSG_LEN == 0 ? (uint_fast32_t) (msg_size / FRAME_MSG_LEN): (uint32_t) (msg_size / FRAME_MSG_LEN) + 1;
        for (uint32_t i = 1; i < num_frames; i++) {
            // Read in the next frame
            uart_write(UART0, read_frame(frame_enc_ptr));

            // Decrypt the frame
            decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext);

            // If the frame is not a body frame, there is an error
            if (frame_dec_ptr->type != 0) {
                uart_write(UART0, ERROR);
                return;
            }

            // Write the decrypted frame to the flash
            if (i == num_frames - 1) {
                // Print out message, but unpadded
                uint32_t index = unpad(frame_dec_start->msg, FRAME_MSG_LEN);
                frame_dec_start->msg[index] = '\0';
            }
            uart_write_str(UART0, frame_dec_start->msg);
        }
        return;
    } else if (msg_size == FRAME_MSG_LEN) {
        // Write the first frame to the python script
        uart_write_str(UART0, frame_dec_start->msg);
    } else if (msg_size < FRAME_MSG_LEN) {
        // Print out message, but unpadded
        uint32_t index = unpad(frame_dec_start->msg, FRAME_MSG_LEN);
        frame_dec_start->msg[index] = '\0';
        uart_write_str(UART0, frame_dec_start->msg);
    }

    for (uint32_t i = 1; i < fw_size; i++) {
        // Read in the next frame
        uart_write(UART0, read_frame(frame_enc_ptr));

        // Decrypt the frame
        decrypt(frame_enc_ptr, i, frame_dec_ptr->plaintext);

        // If the frame is not a body frame, there is an error
        if (frame_dec_ptr->type != 1) {
            uart_write(UART0, ERROR);
            return;
        }

        // Write the decrypted frame to the flash
        uart_write_str(UART0, frame_dec_start->msg);
    }

    /* -------------------------------- This code if for the firmware body frames -------------------------------- */
    // Iterate through body frames
    uint32_t num_frames = fw_size % FRAME_BODY_LEN == 0 ? (uint_fast32_t) (fw_size / FRAME_BODY_LEN): (uint32_t) (fw_size / FRAME_BODY_LEN) + 1;
    for (int i = 0; i < num_frames; i++) {
        // Read in the next frame
        uart_write(UART0, read_frame(frame_enc_ptr));

        // Decrypt the frame
        decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext);
        
        // If the frame is not a body frame, there is an error
        if (frame_dec_ptr->type != 1) {
            uart_write(UART0, ERROR);
            return;
        }

        // Write the decrypted frame to the flash
        if (i == num_frames - 1) {
            // Print out message, but unpadded
            uint32_t index = unpad(frame_dec_body->plaintext, FRAME_BODY_LEN);
            frame_dec_body->plaintext[index] = '\0';
        } else {
            uart_write_str(UART0, frame_dec_body->plaintext);
        }
    }
    
    /* -------------------------------- This code is for the end frame -------------------------------- */
    // Read in the next frame
    uart_write(UART0, read_frame(frame_enc_ptr));
    decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext);

    // If the first frame is not 2, there is an error
    if (frame_dec_ptr->type != 2) {
        uart_write(UART0, ERROR);
        return;
    }
    
    
    // Decrypt the frame
    decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext);
    

    /* -------------------------------- END OF TEST CODE -------------------------------- */

    // int frame_length = 0;
    // int read = 0;
    // uint32_t rcv = 0;

    // uint32_t data_index = 0;
    // uint32_t page_addr = FW_BASE;
    // uint32_t version = 0;
    // uint32_t size = 0;

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

    // // Compare to old version and abort if older (note special case for version 0).
    // // If no metadata available (0xFFFF), accept version 1
    // uint16_t old_version = *fw_version_address;
    // if (old_version == 0xFFFF) {
    //     old_version = 1;
    // }

    // if (version != 0 && version < old_version) {
    //     uart_write(UART0, ERROR); // Reject the metadata.
    //     SysCtlReset();            // Reset device
    //     return;
    // } else if (version == 0) {
    //     // If debug firmware, don't change version
    //     version = old_version;
    // }

    // // Write new firmware size and version to Flash
    // // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    // uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    // program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);

    // uart_write(UART0, OK); // Acknowledge the metadata.

    // /* Loop here until you can get all your characters and stuff */
    // while (1) {

    //     // Get two bytes for the length.
    //     rcv = uart_read(UART0, BLOCKING, &read);
    //     frame_length = (int)rcv << 8;
    //     rcv = uart_read(UART0, BLOCKING, &read);
    //     frame_length += (int)rcv;

    //     // Get the number of bytes specified
    //     for (int i = 0; i < frame_length; ++i) {
    //         data[data_index] = uart_read(UART0, BLOCKING, &read);
    //         data_index += 1;
    //     } // for

    //     // If we filed our page buffer, program it
    //     if (data_index == FLASH_PAGESIZE || frame_length == 0) {
    //         // Try to write flash and check for error
    //         if (program_flash((uint8_t *) page_addr, data, data_index)) {
    //             uart_write(UART0, ERROR); // Reject the firmware
    //             SysCtlReset();            // Reset device
    //             return;
    //         }

    //         // Update to next page
    //         page_addr += FLASH_PAGESIZE;
    //         data_index = 0;

    //         // If at end of firmware, go to main
    //         if (frame_length == 0) {
    //             uart_write(UART0, OK);
    //             break;
    //         }
    //     } // if

    //     uart_write(UART0, OK); // Acknowledge the frame.
    // } // while(1)
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

int decrypt(generic_frame *frame, uint16_t *frame_num, uint8_t *plaintext) {
    // Decrypt the frame
    // Create a new AES context
    Aes aes;

    wc_AesGcmSetKey(&aes, AESKEY, 16); // Set the key

    uint8_t authIn[2] = {*frame_num >> 8, *frame_num & 0xFF};

    // Decrypt the frame
    int result = wc_AesGcmDecrypt(
        & aes,
        plaintext, // Storage for plaintext
        frame->ciphertext, // Storage for ciphertext
        480, // Ciphertext length
        frame->IV, // IV
        16, // IV length
        frame->tag, // Tag
        16, // Tag length
        authIn, // Header
        2 // Header length
    );

    // Verify the tag
    if (result != 0) {
        if (result == AES_GCM_AUTH_E) {
            return AES_GCM_AUTH_E;
        } else {
            return 1;
        }
    }

    *frame_num++;

    return 0;
}
