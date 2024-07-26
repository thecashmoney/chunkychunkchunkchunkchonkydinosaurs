// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Frame constants
#define IV_LEN 16
#define MAC_LEN 16
#define FRAME_MSG_LEN 464
#define FRAME_BODY_LEN 476
#define PLAINTEXT_MINUS_TAG 476

#define MAX_CHUNK_NO 32 // 30KB firmware + padding

// Return messages
#define VERIFY_SUCCESS 0
#define VERIFY_ERR 1

#define FW_LOADED 0
#define FW_ERROR 1


typedef struct pltxt_start_frame {
    uint8_t     IV[16];
    uint8_t     tag[16];
    uint32_t    type;
    uint32_t    version_num;
    uint32_t    total_size;
    uint32_t    msg_size;
    uint8_t     msg[FRAME_MSG_LEN];
} pltxt_start_frame;


typedef struct pltxt_body_frame {
    uint8_t     IV[16];
    uint8_t     tag[16];
    uint32_t    type;
    uint8_t     plaintext[FRAME_BODY_LEN];
} pltxt_body_frame;

typedef struct generic_frame {
    uint8_t             IV[16];
    uint8_t             tag[16];
    uint8_t             ciphertext[480];
} generic_frame;

typedef struct generic_decrypted_frame {
    uint8_t             IV[16];
    uint8_t             tag[16];
    uint32_t            type;
    uint8_t             plaintext[PLAINTEXT_MINUS_TAG];
} generic_decrypted_frame;

typedef struct pltxt_end_frame {
    uint8_t     IV[16];
    uint8_t     tag[16];
    uint32_t    type;
    uint8_t     padding[PLAINTEXT_MINUS_TAG];
} pltxt_end_frame;

long program_flash(void* page_addr, unsigned char * data, unsigned int data_len);

#endif

