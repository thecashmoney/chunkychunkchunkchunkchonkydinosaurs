// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

// Miscellaneous Imports
#include "bootloader.h"
#include "../lib/wolfssl/wolfssl/wolfcrypt/error-crypt.h"
#include "../inc/secrets.h"
#include "../lib/wolfssl/wolfssl/wolfcrypt/error-crypt.h"
#include "../inc/secrets.h"
#include "driverlib/uart.h"

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
int decrypt(generic_frame *frame, uint32_t *frame_num, uint8_t *plaintext);
bool erase_page(void *page_addr, uint32_t num_pages);
void write_firmware(void *mem_addr, uint8_t plaintext);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Frame constants
#define IV_LEN 16
#define MAC_LEN 16
#define FRAME_MSG_LEN 464
#define FRAME_BODY_LEN 476

#define MAX_DECRYPTS 5

// Protocol Constants
#define OK ((unsigned char)0x03)
#define INTEGRITY_ERROR ((unsigned char)0xFC)
#define VERSION_ERROR ((unsigned char)0xFD)
#define TYPE_ERROR ((unsigned char)0xFE)
#define DEC_ERROR ((unsigned char)0xFF)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')
#define OK_DECRYPT ((unsigned char)0x05)
#define DECRYPT_FAIL ((unsigned char)0x06)
#define ALL_ZEROES ((unsigned char)0x08)

// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

uint8_t key[] = AESKEY;

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

    // Check if the peripheral access is enabled.aqsqzxcdvfe gbrhtnsaxwxdcefv bgnhjmzaazsxcd vfbgnhl.swdeedcfrvscfeer
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }
    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led(); chicken nugget

    initialize_uarts(UART0);

    // uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    // uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write(UART0, ((unsigned char)'U'));
            load_firmware();
            // uart_write(UART0, ((unsigned char) 'F'));
            // uart_write(UART0, ((unsigned char) 'U'));
            // uart_write(UART0, ((unsigned char) 'C'));
            // uart_write(UART0, ((unsigned char) 'K'));
            // uart_write_str(UART0, "Loaded new firmware.\n");
            // nl(UART0);
        } else if (instruction == BOOT) {
            // uart_write_str(UART0, "B");
            // uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
    
}


// Reads in the IV and the tag from fw_update.py
void receive_IV_tag(uint8_t *IV, uint8_t *tag)
{
    uint8_t read;
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
    uint8_t rcv;

    // Reads the ciphertext
    for (int i=0; i<480; i++)
    {
        rcv = uart_read(UART0, BLOCKING, &read);
        ciphertext[i] = rcv;
    }
}

// Unpads the plaintext and stores it in plaintext
int unpad(uint8_t* plaintext, uint32_t plaintext_length) 
{
    int index = 0;
    for(int i = plaintext_length; i >= 0; i--) 
    {
        if(plaintext[i] == 0x80) 
            index = i;
    }
    return index;
}

/*
* Reads the packets sent by fw_update.py 
* Sends the ciphertext to decrypt_ciphertext()
*/
// Reads the packets sent by fw_update.py 
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
    //params needed: generic_frame *frame, uint32_t *frame_num, uint8_t *plaintext
    uint32_t tries = 0;
    uint32_t result = 0;
    
    generic_frame f;
    generic_frame *frame_enc_ptr = &f;
    uint32_t frame_index = 0;
    generic_decrypted_frame x;
    generic_decrypted_frame *frame_dec_ptr = &x;
    pltxt_start_frame *frame_dec_start_ptr = (pltxt_start_frame *) frame_dec_ptr;

    result = read_frame(frame_enc_ptr);
    uint32_t i = 0;
    for (i = 0; i < 480; i++) 
    {
        if (frame_enc_ptr->ciphertext[i] != 0)
        {
            break;
        }
    }
    if (i == 479)
    {
        result = ALL_ZEROES;
    }
    uart_write(UART0, result);
    
    // for (int i = 0; i < 16; i++) {
    //     uart_write(UART0, frame_enc_ptr->IV[i]);
    // }
    
    // for (int i = 0; i < 16; i++) {
    //     uart_write(UART0, frame_enc_ptr->tag[i]);
    // }

    // for (int i = 0; i < 480; i++) {
    //     uart_write(UART0, frame_enc_ptr->ciphertext[i]);
    // }
    //write back success message of reading the frame
    
    int dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);

    if (dec_result == 0) {
        uart_write(UART0, OK_DECRYPT);
    }
    else {
        tries = 1;
        while (tries <= MAX_DECRYPTS && (dec_result != 0)) {
            uart_write(UART0, INTEGRITY_ERROR);
            result = read_frame(frame_enc_ptr);
            for (i = 0; i < 480; i++) {
                if (frame_enc_ptr->ciphertext[i] != 0) {
                    break;
                }
            }

            if (i == 479) {
                result = ALL_ZEROES;
            }
            uint32_t i = 0;
            uart_write(UART0, result);
            //result = value of read_frame operation
            dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);
            tries++;
        }
       uart_write(UART0, DECRYPT_FAIL); 
    }


    //writes the frame type
    // uart_write(UART0, frame_dec_start_ptr->type);
    uart_write(UART0, '\x66');
    uint32_t msg_size = frame_dec_start_ptr->msg_size;
    uart_write(UART0, msg_size);
    if (msg_size > FRAME_MSG_LEN) {
        for(uint32_t i = 0; i < FRAME_MSG_LEN; i++) {
            uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
        }
        // Write the first frame to the CAR-SERIAL script (not needed right now)
        // uart_write_str(UART0, frame_dec_start_ptr->msg);

        // Numframes is the total number of start frames
        uint32_t num_frames = msg_size % FRAME_MSG_LEN == 0 ? (uint32_t) (msg_size / FRAME_MSG_LEN) : (uint32_t) (msg_size / FRAME_MSG_LEN) + 1;
        
        for (uint32_t i = 1; i < num_frames; i++) 
        {
            // Read in the next frame + write success/fail message to fw update
            uart_write(UART0, read_frame(frame_enc_ptr));

            //writing message type back to fw update test for testing purposes (please remove later)
            uart_write(UART0, (uint8_t) 0);
            
            // Decrypt the frame
            for (tries = 1; tries <= MAX_DECRYPTS; tries++) {
                // Decrypt the very first start frame
                if (decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext) != 0) {
                    uart_write(UART0, INTEGRITY_ERROR);
                    uart_write(UART0, read_frame(frame_enc_ptr));
                }
            } if (tries == MAX_DECRYPTS) {
                uart_write(UART0, DEC_ERROR);
            }

            // If the frame is not a start frame, there is an error
            if (frame_dec_start_ptr->type != 0) 
            {
                uart_write(UART0, TYPE_ERROR);
                return;
            }

            // If the frame is the last of the start frames, it's padded
            if (i == num_frames - 1) {
                // Print out message, but unpadded
                uint32_t index = unpad(frame_dec_start_ptr->msg, FRAME_MSG_LEN);
                // Ending the start message string at the place where the padding starts using a null byte
                frame_dec_start_ptr->msg[index] = '\0';
                
                // Printing unpadded frame
                for(uint32_t i = 0; i < index; i++) {
                    uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
                }
            } else {
                // Print out the message
                for(uint32_t i = 0; i < FRAME_MSG_LEN; i++) {
                    uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
                }
            }

          //  uart_write_str(UART0, frame_dec_start_ptr->msg);
        }
    } 
    else if (msg_size == FRAME_MSG_LEN) 
    {
        //writing message type back to fw update test for testing purposes (please remove later)
        for(uint32_t i = 0; i < FRAME_MSG_LEN; i++) {
            uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
        }
    } else if (msg_size < FRAME_MSG_LEN) {
        // Writing release message to python
        for(uint32_t i = 0; i < msg_size; i++) {
            uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
        }
    }


   //  uint32_t tries = 0;
    // /* -------------------------------- This code is for the first start frame -------------------------------- */
    // // Actual variable for reading encrypted frames
    // generic_frame frame_encrypted;
    // generic_frame *frame_enc_ptr = &frame_encrypted; // pointer to encrypted frame

    // // Actual variable for storing decrypting frames
    // generic_decrypted_frame frame_decrypted;
    // generic_decrypted_frame *frame_dec_ptr = &frame_decrypted; //pointer to decrypted frame

    // // References to frame_decrypted, but can be read as if they were frame_dec_body / frame_dec_start
    // pltxt_body_frame *frame_dec_body_ptr = (pltxt_body_frame *) frame_dec_ptr;
    // pltxt_start_frame *frame_dec_start_ptr = (pltxt_start_frame *) frame_dec_ptr;
    // pltxt_end_frame *frame_dec_end_ptr = (pltxt_end_frame *) frame_dec_ptr;

    // uart_write(UART0, read_frame(frame_enc_ptr));

    // uint32_t frame_ind = 0;
    // uint32_t *frame_index = &frame_ind;

    // for (tries = 1; tries <= MAX_DECRYPTS; tries++) {
    //     // Decrypt the very first start frame
    //     if (decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext) != 0) {
    //         uart_write(UART0, INTEGRITY_ERROR);
    //         uart_write(UART0, read_frame(frame_enc_ptr));
    //     }
    // } if (tries == MAX_DECRYPTS) {
    //     uart_write(UART0, DEC_ERROR);
    // }

    // // If the first frame is not 0, there is an error
    // if (frame_dec_start_ptr->type != 0) 
    // {
    //     uart_write(UART0, TYPE_ERROR);
    //     return; //probably don't need the return value?
    // }

    // // Saving the metadata
    // uint32_t version = frame_dec_start_ptr->version_num;
    // uint32_t fw_size = frame_dec_start_ptr->total_size;
    // uint32_t msg_size = frame_dec_start_ptr->msg_size;

    // // Making sure the old version isn't smaller than the current version
    // // +casted to uint32 to make the data types uniform.
    // uint32_t old_version = (uint32_t) *fw_version_address;
    // uint32_t old_size = (uint32_t) *fw_size_address;
    
    // if (old_version == 0xFFFF) {
    //     // Version not set
    //     // why would version number automatically be set to 0xFFFF
    //     if(version == 1) {
    //         //initial configuration
    //         *fw_version_address = version;
    //         *fw_size_address = fw_size;
    //     } else {
    //         uart_write(UART0, VERSION_ERROR);
    //         while(UARTBusy(UART0_BASE)) {/*no*/}
    //         SysCtlReset();
    //         return;
    //     }
    // } else if (version < old_version & version != 0) {
    //     // Attempted rollback
    //     // version 0 allowed to be loaded
    //     uart_write(UART0, VERSION_ERROR);
    //     while(UARTBusy(UART0_BASE)){}
    //     SysCtlReset();
    //     return;
    // } else {
    //     // Update version

    //     //updated code: changing the value of version and size at the memory address referenced by fw_version_address and fw_size_address
    //     *fw_version_address = (uint16_t) version;
    //     *fw_size_address = (uint16_t) fw_size;
    //     //able to be casted without bit shift operations because the first 8 bits of the number will always be all 0s
    // }

    // //writing message type back to fw update test for testing purposes (please remove later)
    // uart_write(UART0, (uint8_t) 0);

    
    // /* -------------------------------- This code is for the next start frames -------------------------------- */

    // if (msg_size > FRAME_MSG_LEN) {
    //     for(uint32_t i = 0; i < FRAME_MSG_LEN; i++) {
    //         uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
    //     }
    //     // Write the first frame to the CAR-SERIAL script (not needed right now)
    //     // uart_write_str(UART0, frame_dec_start_ptr->msg);

    //     // Numframes is the total number of start frames
    //     uint32_t num_frames = msg_size % FRAME_MSG_LEN == 0 ? (uint32_t) (msg_size / FRAME_MSG_LEN) : (uint32_t) (msg_size / FRAME_MSG_LEN) + 1;
        
    //     for (uint32_t i = 1; i < num_frames; i++) 
    //     {
    //         // Read in the next frame + write success/fail message to fw update
    //         uart_write(UART0, read_frame(frame_enc_ptr));

    //         //writing message type back to fw update test for testing purposes (please remove later)
    //         uart_write(UART0, (uint8_t) 0);
            
    //         // Decrypt the frame
    //         for (tries = 1; tries <= MAX_DECRYPTS; tries++) {
    //             // Decrypt the very first start frame
    //             if (decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext) != 0) {
    //                 uart_write(UART0, INTEGRITY_ERROR);
    //                 uart_write(UART0, read_frame(frame_enc_ptr));
    //             }
    //         } if (tries == MAX_DECRYPTS) {
    //             uart_write(UART0, DEC_ERROR);
    //         }

    //         // If the frame is not a start frame, there is an error
    //         if (frame_dec_start_ptr->type != 0) 
    //         {
    //             uart_write(UART0, TYPE_ERROR);
    //             return;
    //         }

    //         // If the frame is the last of the start frames, it's padded
    //         if (i == num_frames - 1) {
    //             // Print out message, but unpadded
    //             uint32_t index = unpad(frame_dec_start_ptr->msg, FRAME_MSG_LEN);
    //             // Ending the start message string at the place where the padding starts using a null byte
    //             frame_dec_start_ptr->msg[index] = '\0';
                
    //             // Printing unpadded frame
    //             for(uint32_t i = 0; i < index; i++) {
    //                 uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
    //             }
    //         } else {
    //             // Print out the message
    //             for(uint32_t i = 0; i < FRAME_MSG_LEN; i++) {
    //                 uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
    //             }
    //         }

    //       //  uart_write_str(UART0, frame_dec_start_ptr->msg);
    //     }
    //     return;
    // } 
    // else if (msg_size == FRAME_MSG_LEN) 
    // {
    //     //writing message type back to fw update test for testing purposes (please remove later)
    //     uart_write(UART0, (uint8_t) 0);

    //     // Write the first frame to the python script
    //     // uart_write_str(UART0, frame_dec_start_ptr->msg);
        
    //     for(uint32_t i = 0; i < FRAME_MSG_LEN; i++) {
    //         uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
    //     }
    // } 
    // else {
    //     //writing message type back to fw update test for testing purposes (please remove later)
    //     uart_write(UART0, (uint8_t) 0);

    //     // Print out message, but unpadded
    //     uint32_t index = unpad(frame_dec_start_ptr->msg, FRAME_MSG_LEN);

    //     // Ending update string using a null byte
    //     frame_dec_start_ptr->msg[index] = '\0';
    //     // uart_write_str(UART0, frame_dec_start_ptr->msg);

    //     // Writing unpadded string back to python
    //     for(uint32_t i = 0; i < index; i++) {
    //         uart_write(UART0, (uint8_t)frame_dec_start_ptr->msg[i]);
    //     }
    // }

    // /* -------------------------------- This code if for the firmware body frames -------------------------------- */
    // // Iterate through body frames
    // uint32_t num_frames = fw_size % FRAME_BODY_LEN == 0 ? (uint32_t) (fw_size / FRAME_BODY_LEN): (uint32_t) (fw_size / FRAME_BODY_LEN) + 1;

    // for (int i = 0; i < num_frames; i++) {
    //     // Read in the next frame and write a success/fail message to fw update
    //     uart_write(UART0, read_frame(frame_enc_ptr));

    //     //writing message type back to fw update test for testing purposes (please remove later)
    //     uart_write(UART0, (uint8_t) 1);

    //     // Decrypt the frame, 
    //     for (tries = 1; tries <= MAX_DECRYPTS; tries++) {
    //             // Decrypt the very first start frame
    //             if (decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext) != 0) {
    //                 uart_write(UART0, INTEGRITY_ERROR);
    //                 uart_write(UART0, read_frame(frame_enc_ptr));
    //             }
    //         } if (tries == MAX_DECRYPTS) {
    //             uart_write(UART0, DEC_ERROR);
    //     }
        
    //     // If the frame is not a body frame, there is an error
    //     if (frame_dec_body_ptr->type != 1) {
    //         uart_write(UART0, TYPE_ERROR);
    //         return;
    //     }
 
    //     // Write the decrypted frame to the flash (add function here)
    //     if (i == num_frames - 1) {
    //         // Print out message, but unpadded
    //         uint32_t index = unpad(frame_dec_body_ptr->plaintext, FRAME_BODY_LEN);
    //         frame_dec_body_ptr->plaintext[index] = '\0';
    //     } else {
    //        // uart_write_str(UART0, frame_dec_body_ptr->plaintext);
    //         for(uint32_t i = 0; i < FRAME_BODY_LEN; i++) {
    //             uart_write(UART0, (uint8_t)frame_dec_body_ptr->plaintext[i]);
    //         }
    //     }
    // }
    
    // /* -------------------------------- This code is for the end frame -------------------------------- */
    // // Read in the next frame
    // uart_write(UART0, read_frame(frame_enc_ptr));

    // // Decrypt the frame
    // for (tries = 1; tries <= MAX_DECRYPTS; tries++) {
    //         // Decrypt the very first start frame
    //         if (decrypt(frame_enc_ptr, frame_index, frame_dec_ptr->plaintext) != 0) {
    //             uart_write(UART0, INTEGRITY_ERROR);
    //             uart_write(UART0, read_frame(frame_enc_ptr));
    //         }
    //     } if (tries == MAX_DECRYPTS) {
    //             uart_write(UART0, DEC_ERROR);
    //     }

    // // If the first frame is not 2, there is an error
    // if (frame_dec_end_ptr->type != 2) {
    //     uart_write(UART0, TYPE_ERROR);
    //     return;
    // }
    
    // //writing message type back to fw update test for testing purposes (please remove later)
    // uart_write(UART0, (uint8_t) 2);

    

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


// Erase a given number of pages starting from the page address
bool erase_pages(void *page_addr, uint32_t num_pages)
{
    for (uint32_t i = 0; i < num_pages; i++) 
    {
        uint32_t page_address = (uint32_t) &page_addr + (i * FLASH_PAGESIZE);
        if (FlashErase(page_address) != 0) 
        {
            return -1;  // Failure
        }
    }

    return 0;  // Success
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

    // Erase next 30 FLASH pages
    erase_page(page_addr, 30);  // i think this is passing in the right address 
    //FlashErase((uint32_t) page_addr);


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
        while(UARTBusy(UART0_BASE)){}
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

int decrypt(generic_frame *frame, uint32_t *frame_num, uint8_t *plaintext) {
    // Decrypt the frame
    // Create a new AES context
    Aes aes;
    wc_AesGcmSetKey(&aes, key, 16); // Set the key
    uint8_t authIn[2] = {
        (uint8_t) *frame_num >> 8, 
        (uint8_t) *frame_num & 0xFF
    };

    // :(
    
    // uint8_t authIn[2] = {
    //     (uint8_t) *frame_num & 0xFF,
    //     (uint8_t) *frame_num >> 8
    // };

    // Decrypt the frame
    int result = wc_AesGcmDecrypt(
        & aes,
        plaintext, // Storage for plaintext
        frame->ciphertext, // Reading in from ciphertext
        480, // Ciphertext length
        frame->IV, // IV
        sizeof(frame->IV), // IV length
        frame->tag, // Tag
        sizeof(frame->tag), // Tag length
        authIn, // Header
        sizeof(authIn) // Header length
    );

    return result;
}
