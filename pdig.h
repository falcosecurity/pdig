#pragma once

#include "pdig_debug.h"

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

void set_direction(bool enter);
unsigned long ppm_copy_from_user(void* to, const void* from, unsigned long n);
long ppm_strncpy_from_user(char* to, const char* from, unsigned long n);

