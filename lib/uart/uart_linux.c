// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

/*
 * UART driver code.
 */

#include "uart.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

bool uart2_initialized = 0;

void uart_init(uint8_t uart)
{
  if (uart == UART2)
    uart2_initialized = 1;
}


void uart_write(uint8_t uart, uint32_t data)
{
  if (uart != UART2 || !uart2_initialized) {
      return;
  }
  putc(data, stdout);
  fflush(stdout);
}


uint8_t uart_read(uint8_t uart, int blocking, int *read)
{
  if (uart != UART2 || !uart2_initialized){
    *read = 0;
    return 0;
  }

  *read = 1;
  return (unsigned char) getc(stdin);
}


void uart_write_str(uint8_t uart, char* str)
{
  if (uart != UART2 || !uart2_initialized)
    return;

  puts(str);
  fflush(stdout);
}


inline void nl(uint8_t uart)
{
  uart_write(uart, '\n');
}


void uart_write_hex(uint8_t uart, uint32_t data)
{
  uint32_t nibble;
  
  for (int shift = 28; shift >= 0; shift -=4) {
    nibble = (data >> shift) & 0xF;
    if (nibble > 9) {
      nibble += 0x37;
    } else {
      nibble += 0x30;
    }
    uart_write(uart, nibble);
  }
}


void UART0_IRQHandler(void)
{
  return;
}