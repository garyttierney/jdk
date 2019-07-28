//
// Created by gtierney on 26/07/2019.
//

#ifndef CAPSTONE_HSDIS_PRINTSTREAM_H
#define CAPSTONE_HSDIS_PRINTSTREAM_H

#include "capstone-hsdis.h"
#include <utility>

class PrintStream {
public:
    PrintStream(printf_callback_t _print_callback,
        void* _print_stream,
        bool _append_newline)
        : printf_callback(_print_callback)
        , printf_stream(_print_stream)
        , append_newline(_append_newline)
    {
    }

    template <typename... Args>
    int print(const char* str, Args&&... args)
    {
        return printf_callback(printf_stream, str, std::forward<Args>(args)...);
    }

private:
    printf_callback_t printf_callback;
    void* printf_stream;
    bool append_newline;
};

#endif // CAPSTONE_HSDIS_PRINTSTREAM_H
