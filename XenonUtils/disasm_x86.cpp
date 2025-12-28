#include "disasm_x86.h"
#include <cstring>

namespace x86
{

static const char* g_regNames[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

const char* GetRegName(Reg reg)
{
    if (reg < 8) return g_regNames[reg];
    return "???";
}

// Helper to read unaligned little-endian values safely
template<typename T>
static T ReadUnaligned(const uint8_t* p)
{
    T value;
    std::memcpy(&value, p, sizeof(T));
    return value;
}

// Parse ModR/M byte
// Returns: number of additional bytes consumed (after ModR/M)
static int ParseModRM(const uint8_t* code, size_t maxLen, Operand& op, Reg& regField)
{
    if (maxLen < 1) return -1;
    
    uint8_t modrm = code[0];
    uint8_t mod = (modrm >> 6) & 3;
    regField = static_cast<Reg>((modrm >> 3) & 7);
    uint8_t rm = modrm & 7;
    
    int extraBytes = 0;
    
    if (mod == 3)
    {
        // Register direct
        op.type = OpType::Reg;
        op.reg = static_cast<Reg>(rm);
        return 0;
    }
    
    op.type = OpType::Mem;
    op.base = static_cast<Reg>(rm);
    op.index = X86_REG_NONE;
    op.scale = 1;
    op.disp = 0;
    
    // SIB byte needed?
    if (rm == 4)
    {
        if (maxLen < 2) return -1;
        uint8_t sib = code[1];
        extraBytes = 1;
        
        op.scale = 1 << ((sib >> 6) & 3);
        op.index = static_cast<Reg>((sib >> 3) & 7);
        op.base = static_cast<Reg>(sib & 7);
        
        if (op.index == ESP) op.index = X86_REG_NONE; // ESP can't be index
        if (op.base == EBP && mod == 0)
        {
            op.base = X86_REG_NONE;
            // disp32 follows
            if (maxLen < 6) return -1;
            op.disp = *reinterpret_cast<const int32_t*>(&code[2]);
            return 5;
        }
    }
    else if (rm == 5 && mod == 0)
    {
        // [disp32] - absolute address
        if (maxLen < 5) return -1;
        op.type = OpType::MemDisp;
        op.base = X86_REG_NONE;
        op.disp = *reinterpret_cast<const int32_t*>(&code[1]);
        return 4;
    }
    
    // Displacement
    if (mod == 1)
    {
        if (maxLen < (size_t)(2 + extraBytes)) return -1;
        op.disp = static_cast<int8_t>(code[1 + extraBytes]);
        return extraBytes + 1;
    }
    else if (mod == 2)
    {
        if (maxLen < (size_t)(5 + extraBytes)) return -1;
        op.disp = *reinterpret_cast<const int32_t*>(&code[1 + extraBytes]);
        return extraBytes + 4;
    }
    
    return extraBytes;
}

int Disassemble(const void* code, size_t maxLen, uint32_t address, Insn& out)
{
    if (maxLen < 1) return 0;
    
    // Use default construction to properly initialize Operand fields
    // (X86_REG_NONE is 0xFF, not 0, so memset doesn't work)
    out = Insn{};
    out.address = address;
    out.operandSize = 4;  // Default to 32-bit
    
    const uint8_t* p = static_cast<const uint8_t*>(code);
    const uint8_t* start = p;
    const uint8_t* end = p + maxLen;
    
    // Parse prefixes
    bool hasOpSizePrefix = false;
    uint8_t repPrefix = 0;  // Track which REP prefix: 0xF2 or 0xF3
    while (p < end)
    {
        uint8_t b = *p;
        if (b == 0x66) { hasOpSizePrefix = true; p++; }        // Operand size override
        else if (b == 0x67) { p++; }                            // Address size override
        else if (b == 0xF0) { p++; }                            // LOCK
        else if (b == 0xF2) { repPrefix = 0xF2; p++; }          // REPNE/REPNZ
        else if (b == 0xF3) { out.hasRepPrefix = true; repPrefix = 0xF3; p++; }   // REP/REPE/REPZ
        else if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x64 || b == 0x65) { p++; } // Segment overrides
        else break;
    }
    
    if (hasOpSizePrefix) out.operandSize = 2;
    
    if (p >= end) return 0;
    
    uint8_t opcode = *p++;
    
    switch (opcode)
    {
    // INC r32 (40-47)
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
        out.type = InsnType::Inc;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = static_cast<Reg>(opcode - 0x40);
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
        
    // DEC r32 (48-4F)
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        out.type = InsnType::Dec;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = static_cast<Reg>(opcode - 0x48);
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // PUSH r32 (50-57)
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        out.type = InsnType::Push;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = static_cast<Reg>(opcode - 0x50);
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
        
    // POP r32 (58-5F)
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        out.type = InsnType::Pop;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = static_cast<Reg>(opcode - 0x58);
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // PUSHAD
    case 0x60:
        out.type = InsnType::Pushad;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
        
    // POPAD
    case 0x61:
        out.type = InsnType::Popad;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // PUSH imm8
    case 0x6A:
        if (end - p < 1) return 0;
        out.type = InsnType::Push;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = static_cast<uint32_t>(static_cast<int8_t>(*p));  // Sign-extend
        p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // PUSH imm32
    case 0x68:
        if (end - p < 4) return 0;
        out.type = InsnType::Push;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = ReadUnaligned<uint32_t>(p);
        p += 4;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // POP ES (07)
    case 0x07:
        out.type = InsnType::PopSeg;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // POP SS (17)
    case 0x17:
        out.type = InsnType::PopSeg;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // POP DS (1F)
    case 0x1F:
        out.type = InsnType::PopSeg;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // PUSHFD
    case 0x9C:
        out.type = InsnType::Pushfd;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
        
    // POPFD
    case 0x9D:
        out.type = InsnType::Popfd;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // CDQ (99)
    case 0x99:
        out.type = InsnType::Cdq;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // CWDE (98)
    case 0x98:
        out.type = InsnType::Cwde;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // LAHF (9F) - Load AH from Flags
    case 0x9F:
        out.type = InsnType::Lahf;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // SAHF (9E) - Store AH into Flags
    case 0x9E:
        out.type = InsnType::Sahf;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // BOUND r32, m32&32 (62)
    case 0x62:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Bound;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // ENTER imm16, imm8 (C8)
    case 0xC8:
    {
        if (end - p < 3) return 0;
        out.type = InsnType::Enter;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = ReadUnaligned<uint16_t>(p);
        p += 2;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // HLT (F4)
    case 0xF4:
        out.type = InsnType::Hlt;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // AAA (37) - ASCII Adjust After Addition
    case 0x37:
        out.type = InsnType::Aaa;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // DAS (2F) - Decimal Adjust after Subtraction
    case 0x2F:
        out.type = InsnType::Das;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // DAA (27) - Decimal Adjust after Addition
    case 0x27:
        out.type = InsnType::Daa;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // AAS (3F) - ASCII Adjust after Subtraction
    case 0x3F:
        out.type = InsnType::Aas;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // RETF (CB) - Far Return
    case 0xCB:
        out.type = InsnType::Retf;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // IN AL, imm8 (E4)
    case 0xE4:
        if (end - p < 1) return 0;
        out.type = InsnType::In;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // IN EAX, imm8 (E5)
    case 0xE5:
        if (end - p < 1) return 0;
        out.type = InsnType::In;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // LOOPNE/LOOPNZ (E0)
    case 0xE0:
        if (end - p < 1) return 0;
        out.type = InsnType::Loop;
        out.cond = Condition::NE;
        out.branch_target = address + 2 + static_cast<int8_t>(*p);
        out.is_branch_relative = true;
        p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // LOOPE/LOOPZ (E1)
    case 0xE1:
        if (end - p < 1) return 0;
        out.type = InsnType::Loop;
        out.cond = Condition::E;
        out.branch_target = address + 2 + static_cast<int8_t>(*p);
        out.is_branch_relative = true;
        p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // LOOP (E2)
    case 0xE2:
        if (end - p < 1) return 0;
        out.type = InsnType::Loop;
        out.cond = Condition::None;
        out.branch_target = address + 2 + static_cast<int8_t>(*p);
        out.is_branch_relative = true;
        p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // MOV Sreg, r/m16 (8E)
    case 0x8E:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::MovSeg;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;  // Segment register encoded in reg field
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // POP r/m32 (8F /0)
    case 0x8F:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Pop;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // MOV r/m16, Sreg (8C)
    case 0x8C:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::MovSeg;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;  // Segment register encoded in reg field
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // Flag manipulation instructions
    case 0xF8: out.type = InsnType::Clc; out.length = 1; return 1;  // CLC
    case 0xF9: out.type = InsnType::Stc; out.length = 1; return 1;  // STC
    case 0xFC: out.type = InsnType::Cld; out.length = 1; return 1;  // CLD
    case 0xFD: out.type = InsnType::Std; out.length = 1; return 1;  // STD
    case 0xFA: out.type = InsnType::Cli; out.length = 1; return 1;  // CLI
    case 0xFB: out.type = InsnType::Sti; out.length = 1; return 1;  // STI
    case 0xF5: out.type = InsnType::Cmc; out.length = 1; return 1;  // CMC
    
    // INT1/ICEBP (F1)
    case 0xF1:
        out.type = InsnType::Int1;
        out.length = 1;
        return 1;
    
    // SALC - Set AL from Carry (D6, undocumented)
    case 0xD6:
        out.type = InsnType::Salc;
        out.length = 1;
        return 1;
    
    // ARPL r/m16, r16 (63)
    case 0x63:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Arpl;
        out.operandSize = 2;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // LES r32, m16:32 (C4)
    case 0xC4:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Les;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // LDS r32, m16:32 (C5)
    case 0xC5:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Lds;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // JMP ptr16:32 - Far jump (EA)
    case 0xEA:
    {
        if (end - p < 6) return 0;
        out.type = InsnType::Jmpf;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = ReadUnaligned<uint32_t>(p);  // offset
        p += 4;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = ReadUnaligned<uint16_t>(p);  // segment
        p += 2;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // FWAIT/WAIT (9B)
    case 0x9B:
        out.type = InsnType::Fwait;
        out.length = 1;
        return 1;
    
    // JECXZ rel8 (E3)
    case 0xE3:
        if (end - p < 1) return 0;
        out.type = InsnType::Jecxz;
        out.branch_target = address + 2 + static_cast<int8_t>(*p);
        out.is_branch_relative = true;
        p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // RETF imm16 (CA)
    case 0xCA:
        if (end - p < 2) return 0;
        out.type = InsnType::Retf;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = ReadUnaligned<uint16_t>(p);
        p += 2;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // AAM imm8 (D4)
    case 0xD4:
        if (end - p < 1) return 0;
        out.type = InsnType::Aam;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // AAD imm8 (D5)
    case 0xD5:
        if (end - p < 1) return 0;
        out.type = InsnType::Aad;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // INTO (CE)
    case 0xCE:
        out.type = InsnType::Into;
        out.length = 1;
        return 1;
    
    // INS - Input string from port (6C/6D)
    case 0x6C:
        out.type = InsnType::Ins;
        out.operandSize = 1;
        out.length = 1;
        return 1;
    case 0x6D:
        out.type = InsnType::Ins;
        out.operandSize = 4;
        out.length = 1;
        return 1;
    
    // OUTS - Output string to port (6E/6F)
    case 0x6E:
        out.type = InsnType::Outs;
        out.operandSize = 1;
        out.length = 1;
        return 1;
    case 0x6F:
        out.type = InsnType::Outs;
        out.operandSize = 4;
        out.length = 1;
        return 1;
    
    // OUT imm8, AL (E6)
    case 0xE6:
        if (end - p < 1) return 0;
        out.type = InsnType::Out;
        out.operandSize = 1;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = *p++;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EAX;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // OUT imm8, EAX (E7)
    case 0xE7:
        if (end - p < 1) return 0;
        out.type = InsnType::Out;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = *p++;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EAX;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // IN AL, DX (EC)
    case 0xEC:
        out.type = InsnType::In;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EDX;
        out.length = 1;
        return 1;
    
    // IN EAX, DX (ED)
    case 0xED:
        out.type = InsnType::In;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EDX;
        out.length = 1;
        return 1;
    
    // OUT DX, AL (EE)
    case 0xEE:
        out.type = InsnType::Out;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EDX;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EAX;
        out.length = 1;
        return 1;
    
    // OUT DX, EAX (EF)
    case 0xEF:
        out.type = InsnType::Out;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EDX;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EAX;
        out.length = 1;
        return 1;
    
    // IRET (CF) - Interrupt Return
    case 0xCF:
        out.type = InsnType::Iret;
        out.length = 1;
        return 1;
    
    // XLAT (D7) - Table Lookup Translation
    case 0xD7:
        out.type = InsnType::Xlat;
        out.length = 1;
        return 1;
    
    // CALLF ptr16:32 (9A) - Far Call
    case 0x9A:
        if (end - p < 6) return 0;
        out.type = InsnType::Callf;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = ReadUnaligned<uint32_t>(p);
        p += 4;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = ReadUnaligned<uint16_t>(p);
        p += 2;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // ADD/OR/ADC/SBB/AND/SUB/XOR AL, imm8 (04, 0C, 14, 1C, 24, 2C, 34)
    case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34:
    {
        if (end - p < 1) return 0;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        
        uint8_t op = (opcode >> 3) & 7;
        static const InsnType opTypes[] = { InsnType::Add, InsnType::Or, InsnType::Add, InsnType::Sub, 
                                            InsnType::And, InsnType::Sub, InsnType::Xor, InsnType::Cmp };
        out.type = opTypes[op];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // ADD/OR/ADC/SBB/AND/SUB/XOR EAX, imm32 (05, 0D, 15, 1D, 25, 2D, 35)
    // Or AX, imm16 with 66 prefix
    case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35:
    {
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        
        if (hasOpSizePrefix)
        {
            out.operandSize = 2;
            if (end - p < 2) return 0;
            out.op[1].imm = ReadUnaligned<uint16_t>(p);
            p += 2;
        }
        else
        {
            if (end - p < 4) return 0;
            out.op[1].imm = ReadUnaligned<uint32_t>(p);
            p += 4;
        }
        
        uint8_t op = (opcode >> 3) & 7;
        static const InsnType opTypes[] = { InsnType::Add, InsnType::Or, InsnType::Add, InsnType::Sub, 
                                            InsnType::And, InsnType::Sub, InsnType::Xor, InsnType::Cmp };
        out.type = opTypes[op];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // PUSH ES (06), PUSH CS (0E), PUSH SS (16), PUSH DS (1E)
    case 0x06: case 0x0E: case 0x16: case 0x1E:
        out.type = InsnType::Push;
        out.op[0].type = OpType::Imm;  // Treat segment register as special case
        out.op[0].imm = (opcode >> 3) & 3;  // ES=0, CS=1, SS=2, DS=3
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // TEST AL, imm8 (A8)
    case 0xA8:
        if (end - p < 1) return 0;
        out.type = InsnType::Test;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // TEST EAX, imm32 (A9) or AX, imm16 with 66 prefix
    case 0xA9:
        out.type = InsnType::Test;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        if (hasOpSizePrefix)
        {
            out.operandSize = 2;
            if (end - p < 2) return 0;
            out.op[1].imm = ReadUnaligned<uint16_t>(p);
            p += 2;
        }
        else
        {
            if (end - p < 4) return 0;
            out.op[1].imm = ReadUnaligned<uint32_t>(p);
            p += 4;
        }
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // IMUL r32, r/m32, imm32 (69)
    case 0x69:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Imul;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        
        if (end - p < 4) return 0;
        out.op[2].type = OpType::Imm;
        out.op[2].imm = ReadUnaligned<uint32_t>(p);
        p += 4;
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // IMUL r32, r/m32, imm8 (6B)
    case 0x6B:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Imul;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        
        if (end - p < 1) return 0;
        out.op[2].type = OpType::Imm;
        out.op[2].imm = static_cast<uint32_t>(static_cast<int8_t>(*p));  // Sign-extend
        p++;
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
        
    // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m8, r8 (00-07, 08-0F, 10-17, etc.)
    case 0x00: case 0x08: case 0x10: case 0x18: case 0x20: case 0x28: case 0x30: case 0x38: // r/m8, r8
    {
        if (end - p < 1) return 0;
        out.operandSize = 1;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        
        // Determine operation type from opcode
        uint8_t op = (opcode >> 3) & 7;
        static const InsnType opTypes[] = { InsnType::Add, InsnType::Or, InsnType::Add, InsnType::Sub, 
                                            InsnType::And, InsnType::Sub, InsnType::Xor, InsnType::Cmp };
        out.type = opTypes[op];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m32, r32 (01, 09, 11, 19, 21, 29, 31, 39)
    case 0x01: case 0x09: case 0x11: case 0x19: case 0x21: case 0x29: case 0x31: case 0x39:
    {
        if (end - p < 1) return 0;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        
        uint8_t op = (opcode >> 3) & 7;
        static const InsnType opTypes[] = { InsnType::Add, InsnType::Or, InsnType::Add, InsnType::Sub, 
                                            InsnType::And, InsnType::Sub, InsnType::Xor, InsnType::Cmp };
        out.type = opTypes[op];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r8, r/m8 (02, 0A, 12, 1A, 22, 2A, 32, 3A)
    case 0x02: case 0x0A: case 0x12: case 0x1A: case 0x22: case 0x2A: case 0x32: case 0x3A:
    {
        if (end - p < 1) return 0;
        out.operandSize = 1;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        
        uint8_t op = (opcode >> 3) & 7;
        static const InsnType opTypes[] = { InsnType::Add, InsnType::Or, InsnType::Add, InsnType::Sub, 
                                            InsnType::And, InsnType::Sub, InsnType::Xor, InsnType::Cmp };
        out.type = opTypes[op];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r32, r/m32 (03, 0B, 13, 1B, 23, 2B, 33, 3B)
    case 0x03: case 0x0B: case 0x13: case 0x1B: case 0x23: case 0x2B: case 0x33: case 0x3B:
    {
        if (end - p < 1) return 0;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        
        uint8_t op = (opcode >> 3) & 7;
        static const InsnType opTypes[] = { InsnType::Add, InsnType::Or, InsnType::Add, InsnType::Sub, 
                                            InsnType::And, InsnType::Sub, InsnType::Xor, InsnType::Cmp };
        out.type = opTypes[op];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // CMP AL, imm8
    case 0x3C:
        if (end - p < 1) return 0;
        out.type = InsnType::Cmp;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // CMP EAX, imm32 (or AX, imm16 with 66 prefix)
    case 0x3D:
        out.type = InsnType::Cmp;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Imm;
        if (hasOpSizePrefix)
        {
            out.operandSize = 2;
            if (end - p < 2) return 0;
            out.op[1].imm = ReadUnaligned<uint16_t>(p);
            p += 2;
        }
        else
        {
            if (end - p < 4) return 0;
            out.op[1].imm = ReadUnaligned<uint32_t>(p);
            p += 4;
        }
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // Jcc rel8 (70-7F)
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        if (end - p < 1) return 0;
        out.type = InsnType::Jcc;
        out.cond = static_cast<Condition>(opcode - 0x70);
        out.is_branch_relative = true;
        out.branch_target = address + 2 + static_cast<int8_t>(*p);
        p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // Group 1: imm32/imm8 operations (80, 81, 82, 83)
    case 0x80: // Group 1: r/m8, imm8
    case 0x81: // Group 1: r/m32, imm32
    case 0x82: // Group 1: r/m8, imm8 (duplicate of 80)
    case 0x83: // Group 1: r/m32, imm8 (sign-extended)
    {
        if (end - p < 1) return 0;
        Reg opExt;
        int extra = ParseModRM(p, end - p, out.op[0], opExt);
        if (extra < 0) return 0;
        p += 1 + extra;
        
        // Operation determined by reg field: 0=ADD, 1=OR, 2=ADC, 3=SBB, 4=AND, 5=SUB, 6=XOR, 7=CMP
        static const InsnType opTypes[] = { InsnType::Add, InsnType::Or, InsnType::Add, InsnType::Sub,
                                            InsnType::And, InsnType::Sub, InsnType::Xor, InsnType::Cmp };
        out.type = opTypes[opExt & 7];
        
        out.op[1].type = OpType::Imm;
        if (opcode == 0x80 || opcode == 0x82)
        {
            out.operandSize = 1;
            if (end - p < 1) return 0;
            out.op[1].imm = *p++;
        }
        else if (opcode == 0x81)
        {
            if (hasOpSizePrefix)
            {
                out.operandSize = 2;
                if (end - p < 2) return 0;
                out.op[1].imm = ReadUnaligned<uint16_t>(p);
                p += 2;
            }
            else
            {
                if (end - p < 4) return 0;
                out.op[1].imm = ReadUnaligned<uint32_t>(p);
                p += 4;
            }
        }
        else // 0x83
        {
            if (end - p < 1) return 0;
            out.op[1].imm = static_cast<uint32_t>(static_cast<int8_t>(*p));  // Sign-extend
            p++;
        }
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // TEST r/m8, r8
    case 0x84:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Test;
        out.operandSize = 1;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // TEST r/m32, r32
    case 0x85:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Test;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // XCHG r/m8, r8
    case 0x86:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Xchg;
        out.operandSize = 1;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // XCHG r/m32, r32
    case 0x87:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Xchg;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // MOV r/m8, r8
    case 0x88:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Mov;
        out.operandSize = 1;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // MOV r/m32, r32
    case 0x89:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Mov;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // MOV r8, r/m8
    case 0x8A:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Mov;
        out.operandSize = 1;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // MOV r32, r/m32
    case 0x8B:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Mov;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // LEA r32, m
    case 0x8D:
    {
        if (end - p < 1) return 0;
        out.type = InsnType::Lea;
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[1], regField);
        if (extra < 0) return 0;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = regField;
        p += 1 + extra;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // NOP / XCHG EAX, r32
    case 0x90:
        out.type = InsnType::Nop;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0x91: case 0x92: case 0x93: case 0x94:
    case 0x95: case 0x96: case 0x97:
        out.type = InsnType::Xchg;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::Reg;
        out.op[1].reg = static_cast<Reg>(opcode - 0x90);
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // MOV AL, moffs8 (A0)
    case 0xA0:
        if (end - p < 4) return 0;
        out.type = InsnType::Mov;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::MemDisp;
        out.op[1].disp = ReadUnaligned<int32_t>(p);
        p += 4;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // MOV EAX, moffs32 (A1)
    case 0xA1:
        if (end - p < 4) return 0;
        out.type = InsnType::Mov;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = EAX;
        out.op[1].type = OpType::MemDisp;
        out.op[1].disp = ReadUnaligned<int32_t>(p);
        p += 4;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // MOV moffs8, AL (A2)
    case 0xA2:
        if (end - p < 4) return 0;
        out.type = InsnType::Mov;
        out.operandSize = 1;
        out.op[0].type = OpType::MemDisp;
        out.op[0].disp = ReadUnaligned<int32_t>(p);
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EAX;
        p += 4;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // MOV moffs32, EAX (A3)
    case 0xA3:
        if (end - p < 4) return 0;
        out.type = InsnType::Mov;
        out.op[0].type = OpType::MemDisp;
        out.op[0].disp = ReadUnaligned<int32_t>(p);
        out.op[1].type = OpType::Reg;
        out.op[1].reg = EAX;
        p += 4;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // String operations
    case 0xA4: // MOVSB
        out.type = InsnType::Movs;
        out.operandSize = 1;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xA5: // MOVSD
        out.type = InsnType::Movs;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xA6: // CMPSB
        out.type = InsnType::Cmps;
        out.operandSize = 1;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xA7: // CMPSD
        out.type = InsnType::Cmps;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xAA: // STOSB
        out.type = InsnType::Stos;
        out.operandSize = 1;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xAB: // STOSD
        out.type = InsnType::Stos;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xAC: // LODSB
        out.type = InsnType::Lods;
        out.operandSize = 1;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xAD: // LODSD
        out.type = InsnType::Lods;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xAE: // SCASB
        out.type = InsnType::Scas;
        out.operandSize = 1;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    case 0xAF: // SCASD
        out.type = InsnType::Scas;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // MOV r8, imm8 (B0-B7)
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        if (end - p < 1) return 0;
        out.type = InsnType::Mov;
        out.operandSize = 1;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = static_cast<Reg>(opcode - 0xB0);
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // MOV r32, imm32 (B8-BF) or MOV r16, imm16 with 66 prefix
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        out.type = InsnType::Mov;
        out.op[0].type = OpType::Reg;
        out.op[0].reg = static_cast<Reg>(opcode - 0xB8);
        out.op[1].type = OpType::Imm;
        if (hasOpSizePrefix)
        {
            // 16-bit register and immediate with 66 prefix
            if (end - p < 2) return 0;
            out.operandSize = 2;
            out.op[1].imm = ReadUnaligned<uint16_t>(p);
            p += 2;
        }
        else
        {
            if (end - p < 4) return 0;
            out.op[1].imm = ReadUnaligned<uint32_t>(p);
            p += 4;
        }
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // Group 2: Shift/rotate by imm8 (C0, C1)
    case 0xC0: // r/m8, imm8
    case 0xC1: // r/m32, imm8
    {
        if (end - p < 1) return 0;
        if (opcode == 0xC0) out.operandSize = 1;
        Reg opExt;
        int extra = ParseModRM(p, end - p, out.op[0], opExt);
        if (extra < 0) return 0;
        p += 1 + extra;
        
        if (end - p < 1) return 0;
        out.op[1].type = OpType::Imm;
        out.op[1].imm = *p++;
        
        // 0=ROL, 1=ROR, 2=RCL, 3=RCR, 4=SHL/SAL, 5=SHR, 6=(undefined), 7=SAR
        static const InsnType opTypes[] = { InsnType::Rol, InsnType::Ror, InsnType::Rcl, InsnType::Rcr,
                                            InsnType::Shl, InsnType::Shr, InsnType::Invalid, InsnType::Sar };
        out.type = opTypes[opExt & 7];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // RET imm16
    case 0xC2:
        if (end - p < 2) return 0;
        out.type = InsnType::Ret;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = ReadUnaligned<uint16_t>(p);
        p += 2;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
        
    // RET
    case 0xC3:
        out.type = InsnType::Ret;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // Group 11: MOV r/m, imm (C6, C7)
    case 0xC6: // r/m8, imm8
    case 0xC7: // r/m32, imm32 (or r/m16, imm16 with 66 prefix)
    {
        if (end - p < 1) return 0;
        if (opcode == 0xC6) out.operandSize = 1;
        else if (hasOpSizePrefix) out.operandSize = 2;
        Reg opExt;
        int extra = ParseModRM(p, end - p, out.op[0], opExt);
        if (extra < 0) return 0;
        p += 1 + extra;
        
        // Only MOV is valid (opExt should be 0)
        out.type = InsnType::Mov;
        out.op[1].type = OpType::Imm;
        
        if (opcode == 0xC6)
        {
            if (end - p < 1) return 0;
            out.op[1].imm = *p++;
        }
        else if (hasOpSizePrefix)
        {
            // 16-bit immediate with 66 prefix
            if (end - p < 2) return 0;
            out.op[1].imm = ReadUnaligned<uint16_t>(p);
            p += 2;
        }
        else
        {
            if (end - p < 4) return 0;
            out.op[1].imm = ReadUnaligned<uint32_t>(p);
            p += 4;
        }
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // LEAVE
    case 0xC9:
        out.type = InsnType::Leave;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // INT 3
    case 0xCC:
        out.type = InsnType::Int3;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // INT imm8
    case 0xCD:
        if (end - p < 1) return 0;
        out.type = InsnType::Int;
        out.op[0].type = OpType::Imm;
        out.op[0].imm = *p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // Group 2: Shift/rotate by 1 or CL (D0-D3)
    case 0xD0: // r/m8, 1
    case 0xD1: // r/m32, 1
    case 0xD2: // r/m8, CL
    case 0xD3: // r/m32, CL
    {
        if (end - p < 1) return 0;
        if (opcode == 0xD0 || opcode == 0xD2) out.operandSize = 1;
        Reg opExt;
        int extra = ParseModRM(p, end - p, out.op[0], opExt);
        if (extra < 0) return 0;
        p += 1 + extra;
        
        out.op[1].type = OpType::Imm;
        out.op[1].imm = (opcode == 0xD0 || opcode == 0xD1) ? 1 : 0; // CL encoded as 0
        
        static const InsnType opTypes[] = { InsnType::Rol, InsnType::Ror, InsnType::Rcl, InsnType::Rcr,
                                            InsnType::Shl, InsnType::Shr, InsnType::Invalid, InsnType::Sar };
        out.type = opTypes[opExt & 7];
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // CALL rel32
    case 0xE8:
        if (end - p < 4) return 0;
        out.type = InsnType::Call;
        out.is_branch_relative = true;
        out.branch_target = address + 5 + ReadUnaligned<int32_t>(p);
        p += 4;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // JMP rel32
    case 0xE9:
        if (end - p < 4) return 0;
        out.type = InsnType::Jmp;
        out.is_branch_relative = true;
        out.branch_target = address + 5 + ReadUnaligned<int32_t>(p);
        p += 4;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // JMP rel8
    case 0xEB:
        if (end - p < 1) return 0;
        out.type = InsnType::Jmp;
        out.is_branch_relative = true;
        out.branch_target = address + 2 + static_cast<int8_t>(*p);
        p++;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    
    // x87 FPU instructions (D8-DF)
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    {
        if (end - p < 1) return 0;
        uint8_t modrm = *p;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        
        // Store FPU opcode info for recompiler
        out.fpuOpcode = opcode;
        out.fpuModrm = modrm;
        
        if (mod == 3)
        {
            // Register form (modrm >= 0xC0)
            p++;  // Consume modrm
            int stReg = modrm & 7;  // ST(i) index
            
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(stReg);  // ST(i) encoded in low 3 bits
            
            switch (opcode)
            {
            case 0xD8:  // Arithmetic with ST(0), ST(i)
                switch (reg)
                {
                case 0: out.type = InsnType::Fadd; break;  // FADD ST(0), ST(i)
                case 1: out.type = InsnType::Fmul; break;  // FMUL ST(0), ST(i)
                case 2: out.type = InsnType::Fcom; break;  // FCOM ST(i)
                case 3: out.type = InsnType::Fcom; out.fpuPop = true; break; // FCOMP ST(i)
                case 4: out.type = InsnType::Fsub; break;  // FSUB ST(0), ST(i)
                case 5: out.type = InsnType::Fsub; out.fpuReverse = true; break;  // FSUBR ST(0), ST(i)
                case 6: out.type = InsnType::Fdiv; break;  // FDIV ST(0), ST(i)
                case 7: out.type = InsnType::Fdiv; out.fpuReverse = true; break;  // FDIVR ST(0), ST(i)
                }
                break;
                
            case 0xD9:  // Misc FPU register operations
                if (modrm >= 0xC0 && modrm <= 0xC7) { out.type = InsnType::Fld; }       // FLD ST(i)
                else if (modrm >= 0xC8 && modrm <= 0xCF) { out.type = InsnType::Fxch; } // FXCH ST(i)
                else if (modrm == 0xD0) { out.type = InsnType::Nop; }                   // FNOP
                else if (modrm >= 0xD8 && modrm <= 0xDF) { out.type = InsnType::Fst; out.fpuPop = true; } // FSTP ST(i) - undocumented
                else switch (modrm)
                {
                case 0xE0: out.type = InsnType::Fchs; break;    // FCHS
                case 0xE1: out.type = InsnType::Fabs; break;    // FABS
                case 0xE4: out.type = InsnType::Ftst; break;    // FTST
                case 0xE5: out.type = InsnType::Fxam; break;    // FXAM
                case 0xE8: out.type = InsnType::Fld; break;     // FLD1 (load constant 1.0)
                case 0xE9: out.type = InsnType::Fld; break;     // FLDL2T (load log2(10))
                case 0xEA: out.type = InsnType::Fld; break;     // FLDL2E (load log2(e))
                case 0xEB: out.type = InsnType::Fld; break;     // FLDPI (load pi)
                case 0xEC: out.type = InsnType::Fld; break;     // FLDLG2 (load log10(2))
                case 0xED: out.type = InsnType::Fld; break;     // FLDLN2 (load ln(2))
                case 0xEE: out.type = InsnType::Fld; break;     // FLDZ (load 0.0)
                case 0xF0: out.type = InsnType::F2xm1; break;   // F2XM1
                case 0xF1: out.type = InsnType::Fyl2x; break;   // FYL2X
                case 0xF2: out.type = InsnType::Fptan; break;   // FPTAN
                case 0xF3: out.type = InsnType::Fpatan; break;  // FPATAN
                case 0xF4: out.type = InsnType::Fld; break;     // FXTRACT
                case 0xF5: out.type = InsnType::Fprem; break;   // FPREM1
                case 0xF6: out.type = InsnType::Fdecstp; break; // FDECSTP
                case 0xF7: out.type = InsnType::Fincstp; break; // FINCSTP
                case 0xF8: out.type = InsnType::Fprem; break;   // FPREM
                case 0xF9: out.type = InsnType::Fyl2xp1; break; // FYL2XP1
                case 0xFA: out.type = InsnType::Fsqrt; break;   // FSQRT
                case 0xFB: out.type = InsnType::Fsincos; break; // FSINCOS
                case 0xFC: out.type = InsnType::Frndint; break; // FRNDINT
                case 0xFD: out.type = InsnType::Fscale; break;  // FSCALE
                case 0xFE: out.type = InsnType::Fsin; break;    // FSIN
                case 0xFF: out.type = InsnType::Fcos; break;    // FCOS
                default: out.type = InsnType::Fld; break;
                }
                break;
                
            case 0xDA:  // Conditional moves and FUCOMPP
                if (modrm == 0xE9) { out.type = InsnType::Fucom; out.fpuPop = true; } // FUCOMPP (pops twice)
                else if (modrm >= 0xC0 && modrm <= 0xC7) { out.type = InsnType::Fld; }  // FCMOVB
                else if (modrm >= 0xC8 && modrm <= 0xCF) { out.type = InsnType::Fld; }  // FCMOVE
                else if (modrm >= 0xD0 && modrm <= 0xD7) { out.type = InsnType::Fld; }  // FCMOVBE
                else if (modrm >= 0xD8 && modrm <= 0xDF) { out.type = InsnType::Fld; }  // FCMOVU
                else out.type = InsnType::Fld;
                break;
                
            case 0xDB:  // Conditional moves, FCOMI, FUCOMI
                if (modrm >= 0xC0 && modrm <= 0xC7) { out.type = InsnType::Fld; }      // FCMOVNB
                else if (modrm >= 0xC8 && modrm <= 0xCF) { out.type = InsnType::Fld; } // FCMOVNE
                else if (modrm >= 0xD0 && modrm <= 0xD7) { out.type = InsnType::Fld; } // FCMOVNBE
                else if (modrm >= 0xD8 && modrm <= 0xDF) { out.type = InsnType::Fld; } // FCMOVNU
                else if (modrm == 0xE2) { out.type = InsnType::Fclex; }               // FNCLEX
                else if (modrm == 0xE3) { out.type = InsnType::Finit; }               // FNINIT
                else if (modrm >= 0xE8 && modrm <= 0xEF) { out.type = InsnType::Fcomi; } // FUCOMI
                else if (modrm >= 0xF0 && modrm <= 0xF7) { out.type = InsnType::Fcomi; } // FCOMI
                else out.type = InsnType::Fld;
                break;
                
            case 0xDC:  // Arithmetic with ST(i), ST(0)
                switch (reg)
                {
                case 0: out.type = InsnType::Fadd; break;  // FADD ST(i), ST(0)
                case 1: out.type = InsnType::Fmul; break;  // FMUL ST(i), ST(0)
                case 2: out.type = InsnType::Fcom; break;  // FCOM
                case 3: out.type = InsnType::Fcom; out.fpuPop = true; break;  // FCOMP
                case 4: out.type = InsnType::Fsub; out.fpuReverse = true; break;  // FSUBR ST(i), ST(0)
                case 5: out.type = InsnType::Fsub; break;  // FSUB ST(i), ST(0)
                case 6: out.type = InsnType::Fdiv; out.fpuReverse = true; break;  // FDIVR ST(i), ST(0)
                case 7: out.type = InsnType::Fdiv; break;  // FDIV ST(i), ST(0)
                }
                break;
                
            case 0xDD:  // Misc ST(i) operations
                if (modrm >= 0xC0 && modrm <= 0xC7) { out.type = InsnType::Ffree; }   // FFREE ST(i)
                else if (modrm >= 0xD0 && modrm <= 0xD7) { out.type = InsnType::Fst; } // FST ST(i)
                else if (modrm >= 0xD8 && modrm <= 0xDF) { out.type = InsnType::Fst; out.fpuPop = true; } // FSTP ST(i)
                else if (modrm >= 0xE0 && modrm <= 0xE7) { out.type = InsnType::Fucom; } // FUCOM ST(i)
                else if (modrm >= 0xE8 && modrm <= 0xEF) { out.type = InsnType::Fucom; out.fpuPop = true; } // FUCOMP ST(i)
                else out.type = InsnType::Fld;
                break;
                
            case 0xDE:  // Arithmetic with pop
                switch (reg)
                {
                case 0: out.type = InsnType::Fadd; out.fpuPop = true; break;  // FADDP ST(i), ST(0)
                case 1: out.type = InsnType::Fmul; out.fpuPop = true; break;  // FMULP ST(i), ST(0)
                case 2: out.type = InsnType::Fcom; out.fpuPop = true; break;  // FCOMP  
                case 3: if (modrm == 0xD9) { out.type = InsnType::Fcom; out.fpuPop = true; } break; // FCOMPP
                case 4: out.type = InsnType::Fsub; out.fpuReverse = true; out.fpuPop = true; break;  // FSUBRP ST(i), ST(0)
                case 5: out.type = InsnType::Fsub; out.fpuPop = true; break;  // FSUBP ST(i), ST(0)
                case 6: out.type = InsnType::Fdiv; out.fpuReverse = true; out.fpuPop = true; break;  // FDIVRP ST(i), ST(0)
                case 7: out.type = InsnType::Fdiv; out.fpuPop = true; break;  // FDIVP ST(i), ST(0)
                }
                break;
                
            case 0xDF:  // FSTSW AX, FCOMIP, FUCOMIP
                if (modrm == 0xE0) { out.type = InsnType::Fstsw; }              // FNSTSW AX
                else if (modrm >= 0xE8 && modrm <= 0xEF) { out.type = InsnType::Fcomi; out.fpuPop = true; } // FUCOMIP
                else if (modrm >= 0xF0 && modrm <= 0xF7) { out.type = InsnType::Fcomi; out.fpuPop = true; } // FCOMIP
                else out.type = InsnType::Fld;
                break;
            }
        }
        else
        {
            // Memory form - parse modrm
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            p += 1 + extra;
            
            switch (opcode)
            {
            case 0xD8:  // Single-precision float memory operations
                out.operandSize = 4;  // 32-bit float
                switch (reg)
                {
                case 0: out.type = InsnType::Fadd; break;  // FADD m32fp
                case 1: out.type = InsnType::Fmul; break;  // FMUL m32fp
                case 2: out.type = InsnType::Fcom; break;  // FCOM m32fp
                case 3: out.type = InsnType::Fcom; out.fpuPop = true; break;  // FCOMP m32fp
                case 4: out.type = InsnType::Fsub; break;  // FSUB m32fp
                case 5: out.type = InsnType::Fsub; out.fpuReverse = true; break;  // FSUBR m32fp
                case 6: out.type = InsnType::Fdiv; break;  // FDIV m32fp
                case 7: out.type = InsnType::Fdiv; out.fpuReverse = true; break;  // FDIVR m32fp
                }
                break;
                
            case 0xD9:  // Single-precision float load/store and control
                switch (reg)
                {
                case 0: out.type = InsnType::Fld; out.operandSize = 4; break;      // FLD m32fp
                case 2: out.type = InsnType::Fst; out.operandSize = 4; break;      // FST m32fp
                case 3: out.type = InsnType::Fst; out.operandSize = 4; out.fpuPop = true; break;  // FSTP m32fp
                case 4: out.type = InsnType::Fldenv; break;  // FLDENV m14/28byte
                case 5: out.type = InsnType::Fldcw; out.operandSize = 2; break;    // FLDCW m16
                case 6: out.type = InsnType::Fstenv; break;  // FNSTENV m14/28byte
                case 7: out.type = InsnType::Fstcw; out.operandSize = 2; break;    // FNSTCW m16
                default: out.type = InsnType::Fld; break;
                }
                break;
                
            case 0xDA:  // 32-bit integer operations
                out.fpuInteger = true;
                out.operandSize = 4;
                switch (reg)
                {
                case 0: out.type = InsnType::Fadd; break;  // FIADD m32int
                case 1: out.type = InsnType::Fmul; break;  // FIMUL m32int
                case 2: out.type = InsnType::Fcom; break;  // FICOM m32int
                case 3: out.type = InsnType::Fcom; out.fpuPop = true; break;  // FICOMP m32int
                case 4: out.type = InsnType::Fsub; break;  // FISUB m32int
                case 5: out.type = InsnType::Fsub; out.fpuReverse = true; break;  // FISUBR m32int
                case 6: out.type = InsnType::Fdiv; break;  // FIDIV m32int
                case 7: out.type = InsnType::Fdiv; out.fpuReverse = true; break;  // FIDIVR m32int
                }
                break;
                
            case 0xDB:  // 32-bit integer load/store, 80-bit float load/store
                switch (reg)
                {
                case 0: out.type = InsnType::Fild; out.fpuInteger = true; out.operandSize = 4; break; // FILD m32int
                case 1: out.type = InsnType::Fist; out.fpuInteger = true; out.fpuPop = true; out.operandSize = 4; break; // FISTTP m32int
                case 2: out.type = InsnType::Fist; out.fpuInteger = true; out.operandSize = 4; break; // FIST m32int
                case 3: out.type = InsnType::Fist; out.fpuInteger = true; out.fpuPop = true; out.operandSize = 4; break; // FISTP m32int
                case 5: out.type = InsnType::Fld; out.operandSize = 10; break;    // FLD m80fp (extended precision)
                case 7: out.type = InsnType::Fst; out.operandSize = 10; out.fpuPop = true; break;  // FSTP m80fp
                default: out.type = InsnType::Fld; break;
                }
                break;
                
            case 0xDC:  // Double-precision float memory operations
                out.operandSize = 8;  // 64-bit float
                switch (reg)
                {
                case 0: out.type = InsnType::Fadd; break;  // FADD m64fp
                case 1: out.type = InsnType::Fmul; break;  // FMUL m64fp
                case 2: out.type = InsnType::Fcom; break;  // FCOM m64fp
                case 3: out.type = InsnType::Fcom; out.fpuPop = true; break;  // FCOMP m64fp
                case 4: out.type = InsnType::Fsub; break;  // FSUB m64fp
                case 5: out.type = InsnType::Fsub; out.fpuReverse = true; break;  // FSUBR m64fp
                case 6: out.type = InsnType::Fdiv; break;  // FDIV m64fp
                case 7: out.type = InsnType::Fdiv; out.fpuReverse = true; break;  // FDIVR m64fp
                }
                break;
                
            case 0xDD:  // Double-precision float load/store, state ops
                switch (reg)
                {
                case 0: out.type = InsnType::Fld; out.operandSize = 8; break;      // FLD m64fp
                case 1: out.type = InsnType::Fist; out.fpuInteger = true; out.fpuPop = true; out.operandSize = 8; break; // FISTTP m64int
                case 2: out.type = InsnType::Fst; out.operandSize = 8; break;      // FST m64fp
                case 3: out.type = InsnType::Fst; out.operandSize = 8; out.fpuPop = true; break;  // FSTP m64fp
                case 4: out.type = InsnType::Frstor; break;  // FRSTOR m94/108byte
                case 6: out.type = InsnType::Fsave; break;   // FNSAVE m94/108byte
                case 7: out.type = InsnType::Fstsw; out.operandSize = 2; break;    // FNSTSW m16
                default: out.type = InsnType::Fld; break;
                }
                break;
                
            case 0xDE:  // 16-bit integer operations
                out.fpuInteger = true;
                out.operandSize = 2;
                switch (reg)
                {
                case 0: out.type = InsnType::Fadd; break;  // FIADD m16int
                case 1: out.type = InsnType::Fmul; break;  // FIMUL m16int
                case 2: out.type = InsnType::Fcom; break;  // FICOM m16int
                case 3: out.type = InsnType::Fcom; out.fpuPop = true; break;  // FICOMP m16int
                case 4: out.type = InsnType::Fsub; break;  // FISUB m16int
                case 5: out.type = InsnType::Fsub; out.fpuReverse = true; break;  // FISUBR m16int
                case 6: out.type = InsnType::Fdiv; break;  // FIDIV m16int
                case 7: out.type = InsnType::Fdiv; out.fpuReverse = true; break;  // FIDIVR m16int
                }
                break;
                
            case 0xDF:  // 16/64-bit integer load/store, BCD
                switch (reg)
                {
                case 0: out.type = InsnType::Fild; out.fpuInteger = true; out.operandSize = 2; break; // FILD m16int
                case 1: out.type = InsnType::Fist; out.fpuInteger = true; out.fpuPop = true; out.operandSize = 2; break; // FISTTP m16int
                case 2: out.type = InsnType::Fist; out.fpuInteger = true; out.operandSize = 2; break; // FIST m16int
                case 3: out.type = InsnType::Fist; out.fpuInteger = true; out.fpuPop = true; out.operandSize = 2; break; // FISTP m16int
                case 4: out.type = InsnType::Fld; out.operandSize = 10; break;    // FBLD m80bcd
                case 5: out.type = InsnType::Fild; out.fpuInteger = true; out.operandSize = 8; break; // FILD m64int
                case 6: out.type = InsnType::Fst; out.operandSize = 10; out.fpuPop = true; break;  // FBSTP m80bcd
                case 7: out.type = InsnType::Fist; out.fpuInteger = true; out.fpuPop = true; out.operandSize = 8; break; // FISTP m64int
                default: out.type = InsnType::Fld; break;
                }
                break;
            }
        }
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // Group 4: INC/DEC r/m8 (FE)
    case 0xFE:
    {
        if (end - p < 1) return 0;
        out.operandSize = 1;
        Reg opExt;
        int extra = ParseModRM(p, end - p, out.op[0], opExt);
        if (extra < 0) return 0;
        p += 1 + extra;
        
        // 0=INC, 1=DEC, others undefined
        if (opExt == 0) out.type = InsnType::Inc;
        else if (opExt == 1) out.type = InsnType::Dec;
        else out.type = InsnType::Invalid; // Undefined opcode
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV (F6, F7)
    case 0xF6: // r/m8
    case 0xF7: // r/m16/32
    {
        if (end - p < 1) return 0;
        if (opcode == 0xF6) out.operandSize = 1;
        Reg opExt;
        int extra = ParseModRM(p, end - p, out.op[0], opExt);
        if (extra < 0) return 0;
        p += 1 + extra;
        
        // 0=TEST imm, 1=(undefined), 2=NOT, 3=NEG, 4=MUL, 5=IMUL, 6=DIV, 7=IDIV
        switch (opExt)
        {
        case 0: // TEST r/m, imm
            out.type = InsnType::Test;
            out.op[1].type = OpType::Imm;
            if (opcode == 0xF6)
            {
                if (end - p < 1) return 0;
                out.op[1].imm = *p++;
            }
            else if (hasOpSizePrefix)
            {
                // 16-bit immediate with 66 prefix
                if (end - p < 2) return 0;
                out.op[1].imm = ReadUnaligned<uint16_t>(p);
                p += 2;
            }
            else
            {
                if (end - p < 4) return 0;
                out.op[1].imm = ReadUnaligned<uint32_t>(p);
                p += 4;
            }
            break;
        case 2: out.type = InsnType::Not; break;
        case 3: out.type = InsnType::Neg; break;
        case 4: out.type = InsnType::Mul; break;
        case 5: out.type = InsnType::Imul; break;
        case 6: out.type = InsnType::Div; break;
        case 7: out.type = InsnType::Idiv; break;
        default: out.type = InsnType::Unknown; break;
        }
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // Group 5: INC/DEC/CALL/JMP/PUSH (FF)
    case 0xFF:
    {
        if (end - p < 1) return 0;
        uint8_t modrm = *p;
        Reg opExt = static_cast<Reg>((modrm >> 3) & 7);
        Reg regField;
        int extra = ParseModRM(p, end - p, out.op[0], regField);
        if (extra < 0) return 0;
        p += 1 + extra;
        
        // 0=INC, 1=DEC, 2=CALL, 3=CALL m16:32 (far), 4=JMP, 5=JMP m16:32 (far), 6=PUSH, 7=undefined
        switch (opExt)
        {
        case 0: out.type = InsnType::Inc; break;
        case 1: out.type = InsnType::Dec; break;
        case 2:
            out.type = InsnType::Call;
            break;
        case 3: // CALL far - rare, treat as call
            out.type = InsnType::Call;
            break;
        case 4:
            if (out.op[0].type == OpType::Reg)
                out.type = InsnType::Jmp;
            else
                out.type = InsnType::JmpIndirect;
            break;
        case 5: // JMP far - rare, treat as jmp
            out.type = InsnType::Jmp;
            break;
        case 6: out.type = InsnType::Push; break;
        case 7: out.type = InsnType::Invalid; break; // Undefined opcode
        default: out.type = InsnType::Unknown; break;
        }
        
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    // 0F prefix (2-byte opcodes)
    case 0x0F:
    {
        if (end - p < 1) return 0;
        uint8_t op2 = *p++;
        
        // SSE move instructions (0F 10-11, 28-29)
        if ((op2 == 0x10 || op2 == 0x11))
        {
            // MOVUPS/MOVUPD/MOVSS/MOVSD
            if (end - p < 1) return 0;
            if (repPrefix == 0xF3) {
                out.type = InsnType::Movss;
            } else if (repPrefix == 0xF2) {
                out.type = InsnType::Movsd_sse;
            } else if (hasOpSizePrefix) {
                out.type = InsnType::Movupd;
            } else {
                out.type = InsnType::Movups;
            }
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[op2 == 0x11 ? 0 : 1], regField);
            if (extra < 0) return 0;
            out.op[op2 == 0x11 ? 1 : 0].type = OpType::Reg;
            out.op[op2 == 0x11 ? 1 : 0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVLPS/MOVHLPS (0F 12/13) - Move low packed single
        if (op2 == 0x12 || op2 == 0x13)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movlps;
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[op2 == 0x13 ? 0 : 1], regField);
            if (extra < 0) return 0;
            out.op[op2 == 0x13 ? 1 : 0].type = OpType::Reg;
            out.op[op2 == 0x13 ? 1 : 0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVHPS/MOVLHPS (0F 16/17) - Move high packed single
        if (op2 == 0x16 || op2 == 0x17)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movhps;
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[op2 == 0x17 ? 0 : 1], regField);
            if (extra < 0) return 0;
            out.op[op2 == 0x17 ? 1 : 0].type = OpType::Reg;
            out.op[op2 == 0x17 ? 1 : 0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        if ((op2 == 0x28 || op2 == 0x29))
        {
            // MOVAPS/MOVAPD
            if (end - p < 1) return 0;
            out.type = hasOpSizePrefix ? InsnType::Movapd : InsnType::Movaps;
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[op2 == 0x29 ? 0 : 1], regField);
            if (extra < 0) return 0;
            out.op[op2 == 0x29 ? 1 : 0].type = OpType::Reg;
            out.op[op2 == 0x29 ? 1 : 0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SSE comparison and conversion instructions
        if (op2 == 0x2E || op2 == 0x2F)
        {
            // UCOMISS/UCOMISD (2E), COMISS/COMISD (2F)
            if (end - p < 1) return 0;
            if (op2 == 0x2E) {
                out.type = hasOpSizePrefix ? InsnType::Ucomisd : InsnType::Ucomiss;
            } else {
                out.type = hasOpSizePrefix ? InsnType::Comisd : InsnType::Comiss;
            }
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SSE arithmetic instructions (51-53, 58-5F)
        if (op2 == 0x51 || op2 == 0x52 || op2 == 0x53 || (op2 >= 0x58 && op2 <= 0x5F))
        {
            if (end - p < 1) return 0;
            
            // Determine instruction type based on opcode and prefix
            switch (op2)
            {
            case 0x51: // SQRT
                if (repPrefix == 0xF3) out.type = InsnType::Sqrtss;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Sqrtsd;
                else out.type = InsnType::Sqrtps;  // No prefix = packed
                break;
            case 0x52: // RSQRT (no double-precision version)
                if (repPrefix == 0xF3) out.type = InsnType::Rsqrtss;
                else out.type = InsnType::Rsqrtps;  // No prefix = packed
                break;
            case 0x53: // RCP (no double-precision version)
                if (repPrefix == 0xF3) out.type = InsnType::Rcpss;
                else out.type = InsnType::Rcpps;  // No prefix = packed
                break;
            case 0x58: // ADD
                if (repPrefix == 0xF3) out.type = InsnType::Addss;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Addsd;
                else out.type = InsnType::Addps;  // No prefix = packed
                break;
            case 0x59: // MUL
                if (repPrefix == 0xF3) out.type = InsnType::Mulss;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Mulsd;
                else out.type = InsnType::Mulps;  // No prefix = packed
                break;
            case 0x5A: // CVT
                if (repPrefix == 0xF3) out.type = InsnType::Cvtss2sd;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Cvtsd2ss;
                else out.type = InsnType::Unknown;
                break;
            case 0x5C: // SUB
                if (repPrefix == 0xF3) out.type = InsnType::Subss;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Subsd;
                else out.type = InsnType::Subps;  // No prefix = packed
                break;
            case 0x5D: // MIN
                if (repPrefix == 0xF3) out.type = InsnType::Minss;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Minsd;
                else out.type = InsnType::Minps;  // No prefix = packed
                break;
            case 0x5E: // DIV
                if (repPrefix == 0xF3) out.type = InsnType::Divss;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Divsd;
                else out.type = InsnType::Divps;  // No prefix = packed
                break;
            case 0x5F: // MAX
                if (repPrefix == 0xF3) out.type = InsnType::Maxss;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Maxsd;
                else out.type = InsnType::Maxps;  // No prefix = packed
                break;
            }
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SSE conversion instructions (2A, 2C, 2D) - with various prefixes
        if (op2 == 0x2A || ((op2 == 0x2C || op2 == 0x2D) && (repPrefix != 0 || hasOpSizePrefix)))
        {
            if (end - p < 1) return 0;
            
            switch (op2)
            {
            case 0x2A: // CVTSI2SS/CVTSI2SD/CVTPI2PS/CVTPI2PD
                if (repPrefix == 0xF3) out.type = InsnType::Cvtsi2ss;
                else if (repPrefix == 0xF2) out.type = InsnType::Cvtsi2sd;
                else if (hasOpSizePrefix) out.type = InsnType::Cvtpi2pd;
                else out.type = InsnType::Cvtpi2ps;  // No prefix = CVTPI2PS
                break;
            case 0x2C: // CVTTSS2SI/CVTTSD2SI
                if (repPrefix == 0xF3) out.type = InsnType::Cvttss2si;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Cvttsd2si;
                break;
            case 0x2D: // CVTSS2SI/CVTSD2SI
                if (repPrefix == 0xF3) out.type = InsnType::Cvtss2si;
                else if (repPrefix == 0xF2 || hasOpSizePrefix) out.type = InsnType::Cvtsd2si;
                break;
            }
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SHUFPS (C6)
        if (op2 == 0xC6)
        {
            if (end - p < 2) return 0;  // Need ModRM + imm8
            out.type = InsnType::Shufps;
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            
            // Read shuffle control immediate
            out.op[2].type = OpType::Imm;
            out.op[2].imm = *p++;
            
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // Logical packed operations (54-57)
        if (op2 >= 0x54 && op2 <= 0x57)
        {
            if (end - p < 1) return 0;
            
            switch (op2)
            {
            case 0x54: out.type = InsnType::Andps; break;   // ANDPS
            case 0x55: out.type = InsnType::Andnps; break;  // ANDNPS
            case 0x56: out.type = InsnType::Orps; break;    // ORPS
            case 0x57: out.type = InsnType::Xorps; break;   // XORPS
            }
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // Unpack operations (14-15)
        if (op2 == 0x14 || op2 == 0x15)
        {
            if (end - p < 1) return 0;
            out.type = (op2 == 0x14) ? InsnType::Unpcklps : InsnType::Unpckhps;
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // CMPxx (0F C2) - Compare packed/scalar float with predicate
        if (op2 == 0xC2)
        {
            if (end - p < 2) return 0;  // Need ModRM + imm8
            
            if (repPrefix == 0xF3) out.type = InsnType::Cmpss;
            else if (repPrefix == 0xF2) out.type = InsnType::Cmpsd_sse;
            else if (hasOpSizePrefix) out.type = InsnType::Cmppd;
            else out.type = InsnType::Cmpps;  // No prefix = CMPPS
            
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            
            // Read immediate comparison predicate
            out.op[2].type = OpType::Imm;
            out.op[2].imm = *p++;
            
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // Jcc rel32 (0F 80-8F)
        if (op2 >= 0x80 && op2 <= 0x8F)
        {
            if (end - p < 4) return 0;
            out.type = InsnType::Jcc;
            out.cond = static_cast<Condition>(op2 - 0x80);
            out.is_branch_relative = true;
            out.branch_target = address + 6 + ReadUnaligned<int32_t>(p);
            p += 4;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SETcc r/m8 (0F 90-9F)
        if (op2 >= 0x90 && op2 <= 0x9F)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::SetCC;
            out.cond = static_cast<Condition>(op2 - 0x90);
            out.operandSize = 1;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // CMOVcc r32, r/m32 (0F 40-4F)
        if (op2 >= 0x40 && op2 <= 0x4F)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Cmovcc;
            out.cond = static_cast<Condition>(op2 - 0x40);
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVZX r32, r/m8 (0F B6)
        if (op2 == 0xB6)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movzx;
            out.operandSize = 1;  // Source is 8-bit
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVZX r32, r/m16 (0F B7)
        if (op2 == 0xB7)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movzx;
            out.operandSize = 2;  // Source is 16-bit
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVSX r32, r/m8 (0F BE)
        if (op2 == 0xBE)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movsx;
            out.operandSize = 1;  // Source is 8-bit
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVSX r32, r/m16 (0F BF)
        if (op2 == 0xBF)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movsx;
            out.operandSize = 2;  // Source is 16-bit
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // IMUL r32, r/m32 (0F AF)
        if (op2 == 0xAF)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Imul;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SHLD r/m32, r32, imm8 (0F A4)
        if (op2 == 0xA4)
        {
            if (end - p < 2) return 0;  // Need ModRM + imm8
            out.type = InsnType::Shld;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            p += 1 + extra;
            out.op[2].type = OpType::Imm;
            out.op[2].imm = *p++;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SHLD r/m32, r32, CL (0F A5)
        if (op2 == 0xA5)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Shld;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            out.op[2].type = OpType::Reg;
            out.op[2].reg = ECX;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SHRD r/m32, r32, imm8 (0F AC)
        if (op2 == 0xAC)
        {
            if (end - p < 2) return 0;
            out.type = InsnType::Shrd;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            p += 1 + extra;
            out.op[2].type = OpType::Imm;
            out.op[2].imm = *p++;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SHRD r/m32, r32, CL (0F AD)
        if (op2 == 0xAD)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Shrd;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            out.op[2].type = OpType::Reg;
            out.op[2].reg = ECX;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // BSF r32, r/m32 (0F BC)
        if (op2 == 0xBC)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Bsf;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // BSR r32, r/m32 (0F BD)
        if (op2 == 0xBD)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Bsr;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // RDTSC (0F 31) - Read Time Stamp Counter
        if (op2 == 0x31)
        {
            out.type = InsnType::Rdtsc;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVMSKPS r32, xmm (0F 50)
        if (op2 == 0x50)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movmskps;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // BSWAP r32 (0F C8-CF)
        if (op2 >= 0xC8 && op2 <= 0xCF)
        {
            out.type = InsnType::Bswap;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(op2 - 0xC8);
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // UD2 (0F 0B) - Undefined instruction trap
        if (op2 == 0x0B)
        {
            out.type = InsnType::Ud2;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // LAR r32, r/m32 (0F 02)
        if (op2 == 0x02)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Lar;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // Group 6 (0F 00) - SLDT, STR, LLDT, LTR, VERR, VERW
        if (op2 == 0x00)
        {
            if (end - p < 1) return 0;
            uint8_t modrm = *p;
            uint8_t regOp = (modrm >> 3) & 7;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            
            switch (regOp) {
                case 0: out.type = InsnType::Sldt; break;  // SLDT
                case 1: out.type = InsnType::Str; break;   // STR
                case 2: out.type = InsnType::Lldt; break;  // LLDT
                case 3: out.type = InsnType::Ltr; break;   // LTR
                case 4: out.type = InsnType::Verr; break;  // VERR
                case 5: out.type = InsnType::Verw; break;  // VERW
                default: out.type = InsnType::Invalid; break;
            }
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // CMPXCHG r/m32, r32 (0F B1)
        if (op2 == 0xB1)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Cmpxchg;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // XADD r/m32, r32 (0F C1)
        if (op2 == 0xC1)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Xadd;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // CVTPS2PI mm, xmm/m64 (0F 2D) - without F3/F2 prefix
        // CVTTPS2PI mm, xmm/m64 (0F 2C) - without F3/F2 prefix
        if ((op2 == 0x2D || op2 == 0x2C) && repPrefix == 0)
        {
            if (end - p < 1) return 0;
            out.type = (op2 == 0x2D) ? InsnType::Cvtps2pi : InsnType::Cvttps2pi;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVNTPS m128, xmm (0F 2B) - Non-temporal store of packed single
        if (op2 == 0x2B)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movntps;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + XMM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVD mm, r/m32 (0F 6E) / MOVD r/m32, mm (0F 7E)
        // Also: F3 0F 7E = MOVQ xmm, xmm/m64 (SSE2)
        if (op2 == 0x6E || op2 == 0x7E)
        {
            if (end - p < 1) return 0;
            
            // F3 0F 7E is MOVQ SSE (xmm <- xmm/m64)
            if (op2 == 0x7E && repPrefix == 0xF3)
            {
                out.type = InsnType::Movq_sse;
                Reg regField;
                int extra = ParseModRM(p, end - p, out.op[1], regField);
                if (extra < 0) return 0;
                out.op[0].type = OpType::Reg;
                out.op[0].reg = regField;
                p += 1 + extra;
                out.length = static_cast<uint8_t>(p - start);
                return out.length;
            }
            
            out.type = InsnType::Movd;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[op2 == 0x6E ? 1 : 0], regField);
            if (extra < 0) return 0;
            // Convert GPR code (0-7) to MMX register code (MM0=8 through MM7=15)
            Reg mmReg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            out.op[op2 == 0x6E ? 0 : 1].type = OpType::Reg;
            out.op[op2 == 0x6E ? 0 : 1].reg = mmReg;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVQ mm, mm/m64 (0F 6F) / MOVQ mm/m64, mm (0F 7F)
        // Also: F3 0F 6F = MOVDQU xmm, xmm/m128 (SSE2)
        //       F3 0F 7F = MOVDQU xmm/m128, xmm (SSE2)
        if (op2 == 0x6F || op2 == 0x7F)
        {
            if (end - p < 1) return 0;
            
            // F3 prefix means MOVDQU (SSE2)
            if (repPrefix == 0xF3)
            {
                out.type = InsnType::Movdqu;
                Reg regField;
                int extra = ParseModRM(p, end - p, out.op[op2 == 0x6F ? 1 : 0], regField);
                if (extra < 0) return 0;
                out.op[op2 == 0x6F ? 0 : 1].type = OpType::Reg;
                out.op[op2 == 0x6F ? 0 : 1].reg = regField;
                p += 1 + extra;
                out.length = static_cast<uint8_t>(p - start);
                return out.length;
            }
            
            out.type = InsnType::Movq;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[op2 == 0x6F ? 1 : 0], regField);
            if (extra < 0) return 0;
            // Convert GPR code (0-7) to MMX register code (MM0=8 through MM7=15)
            Reg mmReg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            out.op[op2 == 0x6F ? 0 : 1].type = OpType::Reg;
            out.op[op2 == 0x6F ? 0 : 1].reg = mmReg;
            // If source is also a register (reg-reg form), convert it too
            if (out.op[op2 == 0x6F ? 1 : 0].type == OpType::Reg)
            {
                out.op[op2 == 0x6F ? 1 : 0].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[op2 == 0x6F ? 1 : 0].reg) + MM0);
            }
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // EMMS (0F 77)
        if (op2 == 0x77)
        {
            out.type = InsnType::Emms;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // PCMPGTD mm, mm/m64 (0F 66)
        if (op2 == 0x66)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Pcmpgtd;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // PAND mm, mm/m64 (0F DB)
        if (op2 == 0xDB)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Pand;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // PANDN mm, mm/m64 (0F DF)
        if (op2 == 0xDF)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Pandn;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // POR mm, mm/m64 (0F EB)
        if (op2 == 0xEB)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Por;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // PXOR mm, mm/m64 (0F EF)
        if (op2 == 0xEF)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Pxor;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MMX Packed Add/Subtract instructions
        // PADDB (0F FC), PADDW (0F FD), PADDD (0F FE)
        // PSUBB (0F F8), PSUBW (0F F9), PSUBD (0F FA)
        if (op2 == 0xFC || op2 == 0xFD || op2 == 0xFE ||
            op2 == 0xF8 || op2 == 0xF9 || op2 == 0xFA)
        {
            if (end - p < 1) return 0;
            switch (op2) {
                case 0xFC: out.type = InsnType::Paddb; break;
                case 0xFD: out.type = InsnType::Paddw; break;
                case 0xFE: out.type = InsnType::Paddd; break;
                case 0xF8: out.type = InsnType::Psubb; break;
                case 0xF9: out.type = InsnType::Psubw; break;
                case 0xFA: out.type = InsnType::Psubd; break;
            }
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MMX Packed Compare instructions
        // PCMPEQB (0F 74), PCMPEQW (0F 75), PCMPEQD (0F 76)
        // PCMPGTB (0F 64), PCMPGTW (0F 65), PCMPGTD (0F 66)
        if (op2 == 0x74 || op2 == 0x75 || op2 == 0x76 ||
            op2 == 0x64 || op2 == 0x65 || op2 == 0x66)
        {
            if (end - p < 1) return 0;
            switch (op2) {
                case 0x74: out.type = InsnType::Pcmpeqb; break;
                case 0x75: out.type = InsnType::Pcmpeqw; break;
                case 0x76: out.type = InsnType::Pcmpeqd; break;
                case 0x64: out.type = InsnType::Pcmpgtb; break;
                case 0x65: out.type = InsnType::Pcmpgtw; break;
                case 0x66: out.type = InsnType::Pcmpgtd; break;
            }
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MMX Unpack instructions
        // PUNPCKLBW (0F 60), PUNPCKLWD (0F 61), PUNPCKLDQ (0F 62)
        // PUNPCKHBW (0F 68), PUNPCKHWD (0F 69), PUNPCKHDQ (0F 6A)
        if (op2 == 0x60 || op2 == 0x61 || op2 == 0x62 ||
            op2 == 0x68 || op2 == 0x69 || op2 == 0x6A)
        {
            if (end - p < 1) return 0;
            switch (op2) {
                case 0x60: out.type = InsnType::Punpcklbw; break;
                case 0x61: out.type = InsnType::Punpcklwd; break;
                case 0x62: out.type = InsnType::Punpckldq; break;
                case 0x68: out.type = InsnType::Punpckhbw; break;
                case 0x69: out.type = InsnType::Punpckhwd; break;
                case 0x6A: out.type = InsnType::Punpckhdq; break;
            }
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MMX Pack instructions
        // PACKSSWB (0F 63), PACKSSDW (0F 6B), PACKUSWB (0F 67)
        if (op2 == 0x63 || op2 == 0x6B || op2 == 0x67)
        {
            if (end - p < 1) return 0;
            switch (op2) {
                case 0x63: out.type = InsnType::Packsswb; break;
                case 0x6B: out.type = InsnType::Packssdw; break;
                case 0x67: out.type = InsnType::Packuswb; break;
            }
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MMX Multiply instructions
        // PMULLW (0F D5), PMULHW (0F E5), PMADDWD (0F F5)
        if (op2 == 0xD5 || op2 == 0xE5 || op2 == 0xF5)
        {
            if (end - p < 1) return 0;
            switch (op2) {
                case 0xD5: out.type = InsnType::Pmullw; break;
                case 0xE5: out.type = InsnType::Pmulhw; break;
                case 0xF5: out.type = InsnType::Pmaddwd; break;
            }
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MMX Shift instructions with immediate (0F 71/72/73)
        // These have ModR/M where reg field specifies the operation
        if (op2 == 0x71 || op2 == 0x72 || op2 == 0x73)
        {
            if (end - p < 2) return 0;
            uint8_t modrm = *p;
            uint8_t regOp = (modrm >> 3) & 7;
            
            // Parse the MMX register (mod=11, r/m field)
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>((modrm & 7) + MM0);
            p++;
            
            // Immediate byte
            out.op[1].type = OpType::Imm;
            out.op[1].imm = *p++;
            
            // Determine instruction type based on opcode and reg field
            if (op2 == 0x71) {
                switch (regOp) {
                    case 2: out.type = InsnType::Psrlw; break;
                    case 4: out.type = InsnType::Psraw; break;
                    case 6: out.type = InsnType::Psllw; break;
                    default: out.type = InsnType::Unknown; break;
                }
            } else if (op2 == 0x72) {
                switch (regOp) {
                    case 2: out.type = InsnType::Psrld; break;
                    case 4: out.type = InsnType::Psrad; break;
                    case 6: out.type = InsnType::Pslld; break;
                    default: out.type = InsnType::Unknown; break;
                }
            } else { // 0x73
                switch (regOp) {
                    case 2: out.type = InsnType::Psrlq; break;
                    case 6: out.type = InsnType::Psllq; break;
                    default: out.type = InsnType::Unknown; break;
                }
            }
            
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MMX Shift instructions with mm operand
        // PSRLW (0F D1), PSRLD (0F D2), PSRLQ (0F D3)
        // PSRAW (0F E1), PSRAD (0F E2)
        // PSLLW (0F F1), PSLLD (0F F2), PSLLQ (0F F3)
        if (op2 == 0xD1 || op2 == 0xD2 || op2 == 0xD3 ||
            op2 == 0xE1 || op2 == 0xE2 ||
            op2 == 0xF1 || op2 == 0xF2 || op2 == 0xF3)
        {
            if (end - p < 1) return 0;
            switch (op2) {
                case 0xD1: out.type = InsnType::Psrlw; break;
                case 0xD2: out.type = InsnType::Psrld; break;
                case 0xD3: out.type = InsnType::Psrlq; break;
                case 0xE1: out.type = InsnType::Psraw; break;
                case 0xE2: out.type = InsnType::Psrad; break;
                case 0xF1: out.type = InsnType::Psllw; break;
                case 0xF2: out.type = InsnType::Pslld; break;
                case 0xF3: out.type = InsnType::Psllq; break;
            }
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SSE/MMX Extensions
        // PSHUFW (0F 70), PAVGB (0F E0), PAVGW (0F E3)
        // PMINUB (0F DA), PMAXUB (0F DE), PMINSW (0F EA), PMAXSW (0F EE)
        if (op2 == 0x70)
        {
            if (end - p < 2) return 0;
            out.type = InsnType::Pshufw;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            // Immediate byte for shuffle control
            out.op[2].type = OpType::Imm;
            out.op[2].imm = *p++;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        if (op2 == 0xE0 || op2 == 0xE3 || op2 == 0xDA || op2 == 0xDE || op2 == 0xEA || op2 == 0xEE)
        {
            if (end - p < 1) return 0;
            switch (op2) {
                case 0xE0: out.type = InsnType::Pavgb; break;
                case 0xE3: out.type = InsnType::Pavgw; break;
                case 0xDA: out.type = InsnType::Pminub; break;
                case 0xDE: out.type = InsnType::Pmaxub; break;
                case 0xEA: out.type = InsnType::Pminsw; break;
                case 0xEE: out.type = InsnType::Pmaxsw; break;
            }
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // MOVNTQ mm, m64 (0F E7) - Non-temporal store
        if (op2 == 0xE7)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Movntq;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // Group 7 (0F 01) - SGDT, SIDT, LGDT, LIDT, SMSW, LMSW, INVLPG
        if (op2 == 0x01)
        {
            if (end - p < 1) return 0;
            uint8_t modrm = *p;
            uint8_t regOp = (modrm >> 3) & 7;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            
            switch (regOp) {
                case 0: out.type = InsnType::Sgdt; break;
                case 1: out.type = InsnType::Sidt; break;
                case 2: out.type = InsnType::Lgdt; break;
                case 3: out.type = InsnType::Lidt; break;
                case 4: out.type = InsnType::Smsw; break;
                case 6: out.type = InsnType::Lmsw; break;
                case 7: out.type = InsnType::Invlpg; break;
                default: out.type = InsnType::Invalid; break;
            }
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // CLTS (0F 06) - Clear Task-Switched Flag
        if (op2 == 0x06)
        {
            out.type = InsnType::Clts;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // SYSRET (0F 07) - Return from Fast System Call
        if (op2 == 0x07)
        {
            out.type = InsnType::Sysret;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // INVD (0F 08) - Invalidate Cache
        if (op2 == 0x08)
        {
            out.type = InsnType::Invd;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // WBINVD (0F 09) - Write Back and Invalidate Cache
        if (op2 == 0x09)
        {
            out.type = InsnType::Wbinvd;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // CPUID (0F A2)
        if (op2 == 0xA2)
        {
            out.type = InsnType::Cpuid;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // HADDPS/HADDPD (0F 7C) - Horizontal Add
        if (op2 == 0x7C)
        {
            if (end - p < 1) return 0;
            out.type = hasOpSizePrefix ? InsnType::Haddpd : InsnType::Haddps;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // HSUBPS/HSUBPD (0F 7D) - Horizontal Subtract
        if (op2 == 0x7D)
        {
            if (end - p < 1) return 0;
            out.type = hasOpSizePrefix ? InsnType::Hsubpd : InsnType::Hsubps;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // 3DNow! (0F 0F) - AMD 3DNow! instructions
        if (op2 == 0x0F)
        {
            if (end - p < 2) return 0;  // Need ModRM + suffix byte
            out.type = InsnType::Amd3dnow;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            // 3DNow! has a suffix byte that specifies the actual operation
            out.op[2].type = OpType::Imm;
            out.op[2].imm = *p++;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // BT r/m, r (0F A3) - Bit Test
        if (op2 == 0xA3)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Bt;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // LSS r32, m16:32 (0F B2) - Load far pointer using SS
        if (op2 == 0xB2)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Lss;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // LFS r32, m16:32 (0F B4) - Load far pointer using FS
        if (op2 == 0xB4)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Lfs;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // LGS r32, m16:32 (0F B5) - Load far pointer using GS
        if (op2 == 0xB5)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Lgs;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // BTS r/m, r (0F AB) - Bit Test and Set
        if (op2 == 0xAB)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Bts;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            out.op[1].type = OpType::Reg;
            out.op[1].reg = regField;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // Group 15 (0F AE) - FXSAVE, FXRSTOR, LDMXCSR, STMXCSR, LFENCE, MFENCE, SFENCE
        if (op2 == 0xAE)
        {
            if (end - p < 1) return 0;
            uint8_t modrm = *p;
            uint8_t regOp = (modrm >> 3) & 7;
            uint8_t mod = (modrm >> 6) & 3;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            
            if (mod == 3) {
                // Register form - fence instructions
                switch (regOp) {
                    case 5: out.type = InsnType::Lfence; break;
                    case 6: out.type = InsnType::Mfence; break;
                    case 7: out.type = InsnType::Sfence; break;
                    default: out.type = InsnType::Invalid; break;
                }
            } else {
                // Memory form
                switch (regOp) {
                    case 0: out.type = InsnType::Fxsave; break;
                    case 1: out.type = InsnType::Fxrstor; break;
                    case 2: out.type = InsnType::Ldmxcsr; break;
                    case 3: out.type = InsnType::Stmxcsr; break;
                    default: out.type = InsnType::Invalid; break;
                }
            }
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // PINSRW mm, r32/m16, imm8 (0F C4)
        if (op2 == 0xC4)
        {
            if (end - p < 2) return 0;  // Need ModRM + imm8
            out.type = InsnType::Pinsrw;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = static_cast<Reg>(static_cast<uint8_t>(regField) + MM0);
            p += 1 + extra;
            out.op[2].type = OpType::Imm;
            out.op[2].imm = *p++;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // PMOVMSKB r32, mm (0F D7)
        if (op2 == 0xD7)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Pmovmskb;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[1], regField);
            if (extra < 0) return 0;
            out.op[0].type = OpType::Reg;
            out.op[0].reg = regField;
            // Source is MMX register
            if (out.op[1].type == OpType::Reg)
                out.op[1].reg = static_cast<Reg>(static_cast<uint8_t>(out.op[1].reg) + MM0);
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // PREFETCH hints (0F 18) - NOP with hint
        if (op2 == 0x18)
        {
            if (end - p < 1) return 0;
            out.type = InsnType::Prefetch;
            Reg regField;
            int extra = ParseModRM(p, end - p, out.op[0], regField);
            if (extra < 0) return 0;
            p += 1 + extra;
            out.length = static_cast<uint8_t>(p - start);
            return out.length;
        }
        
        // For now, mark other 0F opcodes as unknown but consume the whole instruction
        // This prevents getting out of sync with the instruction stream
        out.type = InsnType::Unknown;
        out.length = static_cast<uint8_t>(p - start);
        return out.length;
    }
    
    default:
        // Unknown opcode - treat as single byte
        out.type = InsnType::Unknown;
        out.length = 1;
        return 1;
    }
}

bool IsFunctionPrologue(const Insn& insn)
{
    // push ebp is the classic x86 function prologue
    if (insn.type == InsnType::Push && 
        insn.op[0].type == OpType::Reg && 
        insn.op[0].reg == EBP)
    {
        return true;
    }
    return false;
}

bool IsFunctionEpilogue(const Insn& insn)
{
    // ret, leave, or pop ebp before ret
    return insn.type == InsnType::Ret || insn.type == InsnType::Leave;
}

bool IsUnconditionalBranch(const Insn& insn)
{
    return insn.type == InsnType::Jmp || 
           insn.type == InsnType::JmpIndirect ||
           insn.type == InsnType::Ret;
}

} // namespace x86
