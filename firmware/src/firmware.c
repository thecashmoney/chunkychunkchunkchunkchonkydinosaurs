// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <string.h>

#define VERSION_2
#include "mitre_car.h"
#include "uart/uart.h"
#include "usart.h"
#include "util.h"

static const char * FLAG_RESPONSE = "Nice try.";

void getFlag(char * flag) {
    flag = strcpy(flag, FLAG_RESPONSE);
}

int main(void) __attribute__((section(".text.main")));
int main(void) {
    printBanner();
    for (;;) // Loop forever.
    {
        char buff[256];
        int len = prompt(buff, 256);
        if (buff[0] != '\0' && strncmp(buff, "FLAG", len) == 0) {
            getFlag(buff);
            writeLine(buff);
        }
    }
}
