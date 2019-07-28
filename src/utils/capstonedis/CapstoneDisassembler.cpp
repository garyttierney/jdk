#include "CapstoneDisassembler.h"
#include <capstone.h>

void CapstoneDisassemblerOptions::parse(const std::string& options)
{
    if (options.find("att") != std::string::npos) {
        att_syntax = true;
    }
}

std::string CapstoneDisassembler::get_instruction_type(const cs_insn* insn)
{
    if (cs_insn_group(capstone, insn, CS_GRP_CALL)) {
        return "branch";
    } else if (cs_insn_group(capstone, insn, CS_GRP_JUMP)) {
        return "condbranch";
    }

    return "unknown";
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

    InstructionsStarted started { start_va };
    events.emit(started);

    MachineInfo machine_info { "amd64" };
    events.emit(machine_info);

    for (size_t index = 0; index < size; index++) {
        cs_insn insn = instructions[index];
        Instruction event { insn.address };

        events.emit(event);
        output.print("%s ", insn.mnemonic);

        if (cs_insn_group(capstone, &insn, CS_GRP_JUMP) || cs_insn_group(capstone, &insn, CS_GRP_CALL)) {
            uintptr_t jump_addr = get_instruction_branch_target(&insn);
            MemoryAddressEvent jump_addr_event { jump_addr };

            if (events.emit(jump_addr_event) == nullptr) {
                output.print("0x%016" PRIxPTR, jump_addr);
            }
        } else {
            output.print("%s", insn.op_str);
        }

        std::string type = get_instruction_type(&insn);
        InstructionDecoded decoded_event { insn.address + insn.size, type };
        events.emit(decoded_event);
    }

    cs_free(instructions, size);

    InstructionsCompleted completed { end_va };
    events.emit(completed);
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
