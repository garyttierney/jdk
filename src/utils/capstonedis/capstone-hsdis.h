#ifndef CAPSTONE_HSDIS_CAPSTONE_HSDIS_H
#define CAPSTONE_HSDIS_CAPSTONE_HSDIS_H

#ifdef _WIN64
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
#include <stdint.h>

typedef void* (*event_callback_t)(void*, const char*, void*);
typedef int (*printf_callback_t)(void*, const char*, ...);

EXPORT void* decode_instructions_virtual(
    uintptr_t start_va,
    uintptr_t end_va,
    unsigned char* buffer,
    uintptr_t length,
    event_callback_t event_callback,
    void* event_stream,
    printf_callback_t printf_callback,
    void* printf_stream,
    const char* options_ptr,
    int newline /* bool value for nice new line */);
}

#endif // CAPSTONE_HSDIS_CAPSTONE_HSDIS_H