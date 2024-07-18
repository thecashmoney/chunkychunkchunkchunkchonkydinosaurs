// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "uart/uart.h"
#include "usart.h"

int readLine(char * buffer, int max_bytes) {
    int i;
    int ret;
    for (i = 0; i < max_bytes; ++i) {
        // Fetch the received byte value into the variable "received_byte".
        char received_byte = uart_read(UART0, 1, &ret);
        // If the line has ended, terminate the string and break. Otherwise,
        // store the byte and contintue.
        if (received_byte == '\n' || received_byte == '\r') {
            buffer[i] = '\0';
            break;
        } else {
            buffer[i] = received_byte;
        }
    }

    // Reture number of bytes received (length of string).
    return i;
}

void write(const char * buffer) {
    uart_write_str(UART0, (char *)buffer); // Send the byte.
}

void writeLine(const char * buffer) {
    write(buffer);
    nl(UART0);
}

void initializeUSART() {
    uart_init(UART0);
}
