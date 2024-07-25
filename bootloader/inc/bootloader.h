// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define IV_LEN 16
#define MAX_MSG_LEN 256

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Data buffer sizes
#define META_LEN 22 // Excludes message bytes
#define IV_LEN 16
#define MAX_MSG_LEN 256
#define BLOCK_SIZE FLASH_PAGESIZE
#define SIG_SIZE 256
#define CHUNK_SIZE (BLOCK_SIZE + SIG_SIZE)

#define MAX_CHUNK_NO 32 // 30KB firmware + padding

// Return messages
#define VERIFY_SUCCESS 0
#define VERIFY_ERR 1

#define FW_LOADED 0
#define FW_ERROR 1


typedef struct pltxt_start_frame {
    uint16_t    frame_num;
    uint8_t     type;
    uint16_t    version_num;
    uint32_t    total_size;
    uint16_t    msg_size;
    uint8_t     msg[469];
} pltxt_start_frame;


typedef struct pltxt_body_frame {
    uint16_t    frame_num;
    uint8_t     type;
    uint8_t     plaintext[477];
} pltxt_body_frame;

typedef struct generic_frame {
    uint8_t             IV[16];
    uint8_t             tag[16];
    uint8_t             ciphertext[480];
} generic_frame;

long program_flash(void* page_addr, unsigned char * data, unsigned int data_len);

#endif

