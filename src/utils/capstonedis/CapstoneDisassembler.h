#ifndef CAPSTONE_HSDIS_CAPSTONEDISASSEMBLER_H
#define CAPSTONE_HSDIS_CAPSTONEDISASSEMBLER_H

#include "EventStream.h"
#include "PrintStream.h"
#include <capstone.h>
#include <stdexcept>
#include <string>

struct CapstoneDisassemblerOptions {
public:
    bool att_syntax = false;

    void parse(const std::string& options);
};

class CapstoneDisassembler {
public:
    CapstoneDisassembler(CapstoneDisassemblerOptions& options,
        uintptr_t start_va,
        uintptr_t end_va,
        unsigned char* buffer,
        uintptr_t length)
        : start_va(start_va)
        , end_va(end_va)
        , buffer(buffer)
        , length(length)
        , capstone()
    {
        cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &capstone);
        if (err != CS_ERR_OK) {
            throw std::runtime_error(std::string("Failed to open Capstone handle: ") + cs_strerror(err));
        }

        cs_option(capstone, CS_OPT_SYNTAX, options.att_syntax ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL);
        cs_option(capstone, CS_OPT_DETAIL, CS_OPT_ON);
    }

    ~CapstoneDisassembler() { cs_close(&capstone); }

    void disassemble(EventStream& events, PrintStream& output);

private:
    std::string get_instruction_type(const cs_insn* insn);

    csh capstone;
    uintptr_t start_va, end_va;
    unsigned char* buffer;
    uintptr_t length;
};

#endif // CAPSTONE_HSDIS_CAPSTONEDISASSEMBLER_H
