#include "CapstoneDisassembler.h"
#include <capstone.h>

void CapstoneDisassemblerOptions::parse(const std::string& options)
{
    if (options.find("att") != std::string::npos) {
        att_syntax = true;
    }
}

void CapstoneDisassembler::disassemble(EventStream& events,
    PrintStream& output)
{
    cs_insn* instructions;
    size_t size = cs_disasm(capstone, buffer, length, start_va, 0, &instructions);
    if (size == 0) {
        output.print("error: failed to disassemble code, %s",
            cs_strerror(cs_errno(capstone)));
        return;
    }

    events.begin(EVENT_INSNS, start_va);
    events.emit(EVENT_MACHINE, "amd64");

    for (size_t index = 0; index < size; index++) {
        cs_insn insn = instructions[index];

        events.begin(EVENT_INSN, insn.address);
        output.print("%s ", insn.mnemonic);

        if (cs_insn_group(capstone, &insn, CS_GRP_JUMP) || cs_insn_group(capstone, &insn, CS_GRP_CALL)) {
            uintptr_t jump_addr = get_instruction_branch_target(&insn);

            if (events.emit(EVENT_ADDR, jump_addr) == nullptr) {
                output.print("0x%016" PRIxPTR, jump_addr);
            }
        } else {
            output.print("%s", insn.op_str);
        }

        events.end(EVENT_INSN, insn.address + insn.size);
    }

    cs_free(instructions, size);
    events.end(EVENT_INSNS, end_va);
}

intptr_t CapstoneDisassembler::get_instruction_branch_target(const cs_insn* insn)
{
    cs_detail* detail = insn->detail;

    switch (ARCH) {
#define CS_ARCH_CASE(arch, ident) \
    case arch:                    \
        return detail->ident.operands[0].imm;

        CS_ARCH_CASE(CS_ARCH_X86, x86)
        CS_ARCH_CASE(CS_ARCH_ARM, arm)
        CS_ARCH_CASE(CS_ARCH_ARM64, arm64)
        CS_ARCH_CASE(CS_ARCH_MIPS, mips)
        CS_ARCH_CASE(CS_ARCH_PPC, ppc)
        CS_ARCH_CASE(CS_ARCH_SPARC, sparc)
        CS_ARCH_CASE(CS_ARCH_SYSZ, sysz)
        CS_ARCH_CASE(CS_ARCH_XCORE, xcore)
#undef CS_ARCH_CASE
    }

    return 0;
}
