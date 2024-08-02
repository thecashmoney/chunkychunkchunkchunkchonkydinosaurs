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
int erase_pages(uint8_t *page_addr, uint32_t num_pages);
int write_firmware(uint8_t *mem_addr, uint8_t *firmware, uint32_t data_len);

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

// Frame type constants
#define TYPE_START ((unsigned char)0x01)
#define TYPE_BODY ((unsigned char)0x02)
#define TYPE_END ((unsigned char)0x03)

// Status constants to send to fw_update
#define OK ((unsigned char)0x04)
#define OK_DECRYPT ((unsigned char)0x05)
#define DECRYPT_FAIL ((unsigned char)0x07)
#define INTEGRITY_ERROR ((unsigned char)0x06)
#define VERSION_ERROR ((unsigned char)0x08)
#define TYPE_ERROR ((unsigned char)0x09)
#define STOP ((unsigned char)0x10)

// Two characters to start off interaction between bl and update
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')


// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

uint8_t key[] = AESKEY;

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

    // uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    // uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write(UART0, ((unsigned char)'U'));
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
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
void read_frame(generic_frame *frame) 
{
    // read the IV and tag and store them in the generic_frame struct
    receive_IV_tag(frame->IV, frame->tag); 

    // read the ciphertext and store it in the generic_frame struct
    receive_ciphertext(frame->ciphertext);

    // send back a null byte 
    // return OK;

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
    // Address to flash metadata and firmware to
    uint8_t *flash_address = (uint8_t *) FW_BASE;

    // params needed: generic_frame *frame, uint32_t *frame_num, uint8_t *plaintext
    uint32_t tries = 0;
    uint32_t result = 0;
    uint32_t index = 0;
    
    //Generic frame boilerplate :speaking_head: :fire: :100:
    generic_frame f;
    generic_frame *frame_enc_ptr = &f;
    uint32_t frame_index = 0;
    generic_decrypted_frame x;
    generic_decrypted_frame *frame_dec_ptr = &x;

    // Pointers to the decrypted frame, function as start/body/end frame structs
    pltxt_body_frame *frame_dec_body_ptr = (pltxt_body_frame *) frame_dec_ptr;
    pltxt_start_frame *frame_dec_start_ptr = (pltxt_start_frame *) frame_dec_ptr;
    pltxt_end_frame *frame_dec_end_ptr = (pltxt_end_frame *) frame_dec_ptr;

    // Sending the result (either OK msg or NOT OK Message) of reading the first START frame
    read_frame(frame_enc_ptr);

    //Decrypt boilerplate :fire: :fire: :fire:
    int dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);

    //While decryption result is not 0, resend the frame until max decrypts is hit. Otherwise write an OK message.
    if (dec_result == 0) 
    {
        uart_write(UART0, OK_DECRYPT);
    }
    else 
    {
        tries = 1;
        while (tries <= MAX_DECRYPTS && (dec_result != 0)) 
        {
            uart_write(UART0, INTEGRITY_ERROR);
            read_frame(frame_enc_ptr);
            dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);
            tries++;
        }
        if (dec_result != 0) {
            // Decrypt failed more than the max number of times we allow
            uart_write(UART0, DECRYPT_FAIL);
            return;
        } else {
            // Decrypt successful
            uart_write(UART0, OK_DECRYPT);
        }
    }

    if (frame_dec_start_ptr->type != TYPE_START) {
        uart_write(UART0, TYPE_ERROR);
    }

    // Obtaining values of metadata + storing in variables
    uint32_t version = frame_dec_start_ptr->version_num;
    uint32_t fw_size = frame_dec_start_ptr->total_size;
    uint32_t msg_size = frame_dec_start_ptr->msg_size;

    // Erases 30 pages of memory to write the stuff
    uint32_t pages_delete = ((uint32_t) ((msg_size + fw_size) / FLASH_PAGESIZE)) + 1;
    erase_pages(flash_address, pages_delete);

    flash_address = FW_BASE;
    
    // // Making sure the old version isn't smaller than the current version
    // // +casted to uint32 to make the data types uniform.
    uint32_t old_version = (uint32_t) *fw_version_address;
    uint32_t old_size = (uint32_t) *fw_size_address;
    if (old_version == 0xFFFF) 
    {
        // Version not set
        if(version == 1) 
        {
            //initial configuration
            // *fw_version_address = (uint16_t)version;
            // *fw_size_address = (uint16_t)fw_size;
            uint32_t metadata = ((fw_size & 0xFFFF) << 16) | (version & 0xFFFF);
            program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);
        } else 
        {
            uart_write(UART0, VERSION_ERROR);
            while(UARTBusy(UART0_BASE)) {/*no*/}
            SysCtlReset();
            return;
        }
    } else if (version < old_version && version != 0) 
    {
        // Attempted rollback
        // version 0 allowed to be loaded
        uart_write(UART0, VERSION_ERROR);
        while(UARTBusy(UART0_BASE)){}
        SysCtlReset();
        return;
    } else 
    {
        //change the value of version and size at the memory address referenced by fw_version_address and fw_size_address
        // *fw_version_address = (uint16_t) version;
        // *fw_size_address = (uint16_t) fw_size;
        uint32_t metadata = ((fw_size & 0xFFFF) << 16) | (version & 0xFFFF);
        program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);
    }

    //writes the frame type
    //uart_write(UART0, frame_dec_start_ptr->type);
    uart_write(UART0, OK);
    //change the type not to be hard-coded
    frame_index++;



    // Numframes is the total number of start frames
    uint32_t num_frames = msg_size % FRAME_MSG_LEN == 0 ? (uint32_t) (msg_size / FRAME_MSG_LEN) : (uint32_t) (msg_size / FRAME_MSG_LEN) + 1;
    uint8_t has_padding = msg_size % FRAME_MSG_LEN != 0;
    uint8_t *msg_location = (uint8_t *) (flash_address + (fw_size + (FRAME_BODY_LEN - (fw_size % FRAME_BODY_LEN))));

    if (msg_size <= FRAME_MSG_LEN) {
        if (has_padding) {
            // Find index of the padding in the release message string
            index = unpad(frame_dec_start_ptr->msg, msg_size);
            frame_dec_start_ptr->msg[index] = '\0';

            // Writing the release message to after where the firmware will be
            write_firmware(msg_location, frame_dec_start_ptr->msg, FRAME_MSG_LEN);
            msg_location += FRAME_MSG_LEN;
        } else {
            // Writing the release message to after where the firmware will be
            write_firmware(msg_location, frame_dec_start_ptr->msg, FRAME_MSG_LEN);
            msg_location += FRAME_MSG_LEN;
        }
    } else {
        // Writing the release message to after where the firmware will be
        write_firmware(msg_location, frame_dec_start_ptr->msg, FRAME_MSG_LEN);
        msg_location += FRAME_MSG_LEN;
    }

    for (uint32_t i = 1; i < num_frames; i++) {
        // Read in the next frame + write success/fail message to fw update
        read_frame(frame_enc_ptr);

        //Decrypt boilerplate :fire: :fire: :fire:
        dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);

        //While decryption result is not 0, resend the frame until max decrypts is hit. Otherwise write an OK message.
        if (dec_result == 0) {
            uart_write(UART0, OK_DECRYPT);
        } else {
            tries = 1;
            while (tries <= MAX_DECRYPTS && (dec_result != 0)) {
                uart_write(UART0, INTEGRITY_ERROR);
                read_frame(frame_enc_ptr);
                dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);
                tries++;
            }
            if (dec_result != 0) {
                // Decrypt failed more than the max number of times we allow
                uart_write(UART0, DECRYPT_FAIL);
                return;
            } else {
                // Decrypt successful
                uart_write(UART0, OK_DECRYPT);
            }
        }
        // If the frame is not a start frame, there is an error
        if (frame_dec_start_ptr->type != TYPE_START) {
            uart_write(UART0, TYPE_ERROR);
            return;
        }
        
        //Writing message type back to fw update test for testing purposes (please remove later)
        uart_write(UART0, OK);
        frame_index++;


        // If the frame is the last of the start frames, it's padded
        if ((i == num_frames - 1) && has_padding) {
            // Print out message, but unpadded
            uint32_t index = unpad(frame_dec_start_ptr->msg, FRAME_MSG_LEN);
            frame_dec_start_ptr->msg[index] = '\0';

            // Writing the release message to after where the firmware will be
            write_firmware(msg_location, frame_dec_start_ptr->msg, FRAME_MSG_LEN);
            msg_location += FRAME_MSG_LEN;
        } else {
            // Writing the release message to after where the firmware will be
            write_firmware(msg_location, frame_dec_start_ptr->msg, FRAME_MSG_LEN);
            msg_location += FRAME_MSG_LEN;
        }
    }

    // ----------------------------- END FIRMWARE START MESSAGE READING -- START OF FIRMWARE BODY FRAMES ---------------------------------- //
    // Setting the flash_address pointer back to where the firmware goes
    flash_address = (uint8_t *) FW_BASE;

    // Iterate through body frames

    // Calculate the expected number of frames that fw update should send
    if (fw_size % FRAME_BODY_LEN == 0) {
        num_frames = (uint32_t) (fw_size / FRAME_BODY_LEN);
    } else {
        num_frames = (uint32_t) (fw_size / FRAME_BODY_LEN) + 1;
    }
    

    for (int i = 0; i < num_frames; i++) {
        // Read in the next frame and write a success/fail message to fw update
        read_frame(frame_enc_ptr);
        
        //Decryption - save result of decryption operation in dec_result
        dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);

        //While decryption result is not 0, resend the frame until max decrypts is hit. Otherwise write an OK message.
        if (dec_result == 0) { 
            uart_write(UART0, OK_DECRYPT);
        } else {
            tries = 1;
            while (tries <= MAX_DECRYPTS && (dec_result != 0)) {
                uart_write(UART0, INTEGRITY_ERROR);
                read_frame(frame_enc_ptr);
                dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);
                tries++;
            }
            if (dec_result != 0) {
                // Decrypt failed more than the max number of times we allow
                uart_write(UART0, DECRYPT_FAIL);
                return;
            } else {
                // Decrypt successful just after max num of tries
                uart_write(UART0, OK_DECRYPT);
            }
        } 
    
        
        // If the frame is not a body frame, there is an error
        if (frame_dec_body_ptr->type != TYPE_BODY) {
            uart_write(UART0, TYPE_ERROR);
            return;
        }

        // Writing the release message to after where the firmware will be
        write_firmware(flash_address, frame_dec_body_ptr->plaintext, FRAME_BODY_LEN);
        flash_address += FRAME_BODY_LEN;

        uart_write(UART0, OK);

        // Writing a frame of the firmware to flash 


        //write msg size: remove this later

        frame_index++;
 
        // If there is an unpadded frame and if this is the last frame, unpad it
        if ((i == num_frames - 1) && (fw_size % FRAME_BODY_LEN != 0)) {
            // Print out unpadded message
            uint32_t index = unpad(frame_dec_body_ptr->plaintext, FRAME_BODY_LEN);
            // frame_dec_body_ptr->plaintext[index] = '\0';
            // insert function here to write to flash here (unpadded firmware data)
        } else {
            // Print out firmware stuff - remove later
            // insert function here to write to flash here (full frame of firmware data)
        }
    }
    
    /* -------------------------------- End of code for reading body frames, starting read for end frame -------------------------------- */
    // Read in the next frame
    read_frame(frame_enc_ptr);

    //Decryption - save result of decryption operation in dec_result
    dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);

    /* While decryption result is not 0, resend the frame until max decrypts is hit. Otherwise write an OK message. */
    if (dec_result == 0) { 
        uart_write(UART0, OK_DECRYPT);
    } else {
        tries = 1;
        while (tries <= MAX_DECRYPTS && (dec_result != 0)) {
            uart_write(UART0, INTEGRITY_ERROR);
            read_frame(frame_enc_ptr);
            dec_result = decrypt(frame_enc_ptr, &frame_index, frame_dec_ptr->plaintext);
            tries++;
        }
        if (dec_result != 0) {
            /* Decrypt failed more than the max number of times we allow */
            uart_write(UART0, DECRYPT_FAIL);
            return;
        } else {
            /* Decrypt was successful, write OK message back to python */
            uart_write(UART0, OK_DECRYPT);
        }
    }

    /* If the first frame is not 2, there is an error */
    if (frame_dec_end_ptr->type != TYPE_END) {
        uart_write(UART0, TYPE_ERROR);
        return;
    }

    /* Sending back the end frame type to the python - remove later */ 
    uart_write(UART0, STOP);
}

/* Erase a given number of pages starting from the page address */ 
int erase_pages(uint8_t *page_addr, uint32_t num_pages) {
    // Assuming 16mHz is the clock speed idk what it is or how that works but it works
    // Number after the * is the amount to wait in ms
    volatile uint32_t cycles = (16000000 / 1000) * 500;
    uint32_t twelves = (uint32_t) (num_pages / 12);
    volatile uint32_t cycle = 0;
    for (uint32_t twelve = 0; twelve < twelves; twelve++) {
        cycle = 0;
        for (uint32_t page = 0; page < 12; page++) {
            if (FlashErase((uint32_t) page_addr) != 0) {
                uart_write(UART0, TYPE_ERROR);  // Failure
                return - 1;
            }
            page_addr += FLASH_PAGESIZE;
        }
        while (cycle < cycles) {
            cycle++;
        }
    }
    for (uint32_t page = 0; page < num_pages % 12; page++) {
        if (FlashErase((uint32_t) page_addr) != 0) {
            uart_write(UART0, TYPE_ERROR);  // Failure
            return - 1;
        }
        page_addr += FLASH_PAGESIZE;
    }
    while (cycle < cycles) {
        cycle++;
    }

    return 0;  // Success
}

/*
 * --------------------------------------------------------------
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 * --------------------------------------------------------------
 */


int write_firmware(uint8_t* page_addr, uint8_t *firmware, uint32_t data_len) {
    uint32_t word = 0;
    int result;
    uint32_t i;
 
    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE != 0) {
        // Get number of unused bytes
        uint32_t remainder = data_len % FLASH_WRITESIZE;
        int num_full_words = data_len / FLASH_WRITESIZE;

        // Program up to the last word
        result = FlashProgram((unsigned long *)firmware, (uint32_t) page_addr, num_full_words);
        if (result != 0) {
            return result;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < remainder; i++) {
            word = (word >> 8) | (firmware[num_full_words + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = 0; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word (in case it is not div by 4)
        return FlashProgram(&word, (uint32_t) page_addr + num_full_words, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)firmware, (uint32_t) page_addr, data_len);
    }
}



long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // // Erase next 30 FLASH pages
    // erase_page(page_addr, 30);  // i think this is passing in the right address 
    // FlashErase((uint32_t) page_addr);


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
    fw_release_message_address = (uint8_t *) (FW_BASE + (fw_size + (FRAME_BODY_LEN - (fw_size % FRAME_BODY_LEN))));
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

// Decrypt the frame
int decrypt(generic_frame *frame, uint32_t *frame_num, uint8_t *plaintext) {
    // Create a new AES context
    Aes aes;
    wc_AesGcmSetKey(&aes, key, 16); // Set the key
    uint8_t authIn[2] = {
        (uint8_t) *frame_num & 0xFF,
        (uint8_t) *frame_num >> 8
    };
 
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