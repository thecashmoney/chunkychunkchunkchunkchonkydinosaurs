// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

// UART Channels
#define UART0 0
#define UART1 1
#define UART2 2

// Read modes
#define NONBLOCKING 0
#define BLOCKING 1

// Device control
#define RESET_SYMBOL 0x20

// Types
#include <stdint.h>

// Function prototypes
void uart_init(uint8_t uart);
uint8_t uart_read(uint8_t uart, int blocking, int *read);
void uart_write(uint8_t uart, uint32_t data);
void uart_write_hex(uint8_t uart, uint32_t data);
void uart_write_str(uint8_t uart, char *str);
void nl(uint8_t uart);
void initialize_uarts();