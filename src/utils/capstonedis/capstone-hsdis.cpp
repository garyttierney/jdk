#include "capstone-hsdis.h"

#include "CapstoneDisassembler.h"
#include "EventStream.h"
#include "PrintStream.h"

EXPORT void* decode_instructions_virtual(uintptr_t start_va,
    uintptr_t end_va,
    unsigned char* buffer,
    uintptr_t length,
    event_callback_t event_callback,
    void* event_stream,
    printf_callback_t printf_callback,
    void* printf_stream,
    const char* options_ptr,
    int newline)
{
    EventStream events { event_callback, event_stream };
    PrintStream output { printf_callback, printf_stream, newline == 1 };

    try {
        CapstoneDisassemblerOptions disassembler_opts;

        if (options_ptr != nullptr) {
            disassembler_opts.parse(std::string(options_ptr));
        }

        CapstoneDisassembler disassembler { disassembler_opts, start_va, end_va, buffer, length };
        disassembler.disassemble(events, output);
    } catch (std::runtime_error& err) {
        output.print("%s", err.what());
    }

    return nullptr;
}
