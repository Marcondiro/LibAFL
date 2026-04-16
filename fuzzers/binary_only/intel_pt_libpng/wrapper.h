#ifndef WRAPPER_H
#define WRAPPER_H

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#endif // WRAPPER_H
