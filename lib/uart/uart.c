// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include <stdbool.h>

// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
#include "inc/hw_types.h" // Boolean type
#include "inc/hw_gpio.h" // GPIO macros (for UART initialization)

// Driver API Imports
#include "driverlib/uart.h" // UART API
#include "driverlib/sysctl.h" // Stystem Control API (clock/reset)
#include "driverlib/gpio.h" // GPIO (for UART setup)
#include "driverlib/pin_map.h"

// Application Imports
#include "uart.h"

void uart_init(uint8_t uart)
{
  unsigned long uart_base;
  int rx_int_enable = 0;
  switch (uart){
    case UART0:
      uart_base = UART0_BASE;
      rx_int_enable = 1;
      break;
    case UART1:
      uart_base = UART1_BASE;
      break;
    case UART2:
      uart_base = UART2_BASE;
      break;
    default:
      return;
  }

  UARTDisable(uart_base);
  UARTConfigSetExpClk(uart_base, SysCtlClockGet(), 115200, (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));
  if (rx_int_enable) UARTIntEnable(uart_base, UART_INT_RX);
  UARTEnable(uart_base);
}

void initialize_uarts(){
  // Enable GPIO Peripherals used by UARTs
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA); // UART0

  // Enable UART0
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART0);

  // Configure pins
  GPIOPinConfigure(GPIO_PA0_U0RX);
  GPIOPinConfigure(GPIO_PA1_U0TX);
  GPIOPinTypeUART(GPIO_PORTA_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Use the internal 16MHz oscillator as the UART clock source.
  UARTClockSourceSet(UART0_BASE, UART_CLOCK_PIOSC);

  UARTConfigSetExpClk(UART0_BASE, SysCtlClockGet(), 115200, (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));
}

uint8_t uart_read(uint8_t uart, int blocking, int *read)
{
  unsigned long uart_base;
  switch (uart){
    case UART0:
      uart_base = UART0_BASE;
      break;
    case UART1:
      uart_base = UART1_BASE;
      break;
    case UART2:
      uart_base = UART2_BASE;
      break;
    default:
      *read = 0;
      return 0;
  }

  if (blocking) {
    *read = 1;
    return UARTCharGet(uart_base) & 0xFF;
  } 

  if (UARTCharsAvail(uart_base)) { // Check if byte is available (FIFO full)
    *read = 1;
    return UARTCharGet(uart_base) & 0xFF; // Return Rx value
  } else {
    *read = 0;
    return 0;
  }
}

void uart_write(uint8_t uart, uint32_t data)
{
  unsigned long uart_base;
  switch (uart){
    case UART0:
      uart_base = UART0_BASE;
      break;
    case UART1:
      uart_base = UART1_BASE;
      break;
    case UART2:
      uart_base = UART2_BASE;
      break;
    default:
      return;
  }

  // Always blocking write
  UARTCharPut(uart_base, (unsigned char)data);
}

void uart_write_str(uint8_t uart, char *str) {
  while (*str) { // Loop until null terminator
    uart_write(uart, (uint32_t)*str++);
  }
}

inline void nl(uint8_t uart) {
  uart_write(uart, '\n');
}

void uart_write_hex(uint8_t uart, uint32_t data) {
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

// UART0 ISR : Reset if received 0x20
void UART0_IRQHandler(void)
{
  UARTIntClear(UART0_BASE, UART_INT_RX);
  if (UARTCharGet(UART0_BASE) == RESET_SYMBOL){
    SysCtlReset();
  }
}