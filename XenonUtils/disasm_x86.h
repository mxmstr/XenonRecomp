#pragma once

#include <cstdint>
#include <cstddef>

namespace x86
{
    // x86 instruction types we care about for analysis
    enum class InsnType
    {
        Unknown,
        // Function prologue/epilogue
        Push,           // push reg
        Pop,            // pop reg
        PopSeg,         // pop segment register (ES, SS, DS)
        Mov,            // mov reg, reg/imm/mem
        Movzx,          // movzx - move with zero extend
        Movsx,          // movsx - move with sign extend
        Lea,            // lea - load effective address
        Sub,            // sub esp, imm
        Add,            // add esp, imm
        Ret,            // ret / retn
        Leave,          // leave
        Enter,          // enter
        // Branches
        Jmp,            // jmp rel/reg/mem
        JmpIndirect,    // jmp [mem] - for jump tables
        Jcc,            // conditional jumps
        Call,           // call rel/reg/mem
        // Comparison (for switch detection)
        Cmp,            // cmp reg, imm
        Test,           // test reg, reg
        // Arithmetic
        Inc,            // inc reg
        Dec,            // dec reg
        Neg,            // neg reg/mem
        Not,            // not reg/mem
        Mul,            // mul (unsigned multiply)
        Imul,           // imul (signed multiply)
        Div,            // div (unsigned divide)
        Idiv,           // idiv (signed divide)
        // Logical
        And,            // and
        Or,             // or
        Xor,            // xor
        // Shifts/rotates
        Shl,            // shl/sal - shift left
        Shr,            // shr - shift right logical
        Sar,            // sar - shift right arithmetic
        Rol,            // rol - rotate left
        Ror,            // ror - rotate right
        Rcl,            // rcl - rotate left through carry
        Rcr,            // rcr - rotate right through carry
        // String operations
        Movs,           // movsb/movsw/movsd
        Stos,           // stosb/stosw/stosd
        Lods,           // lodsb/lodsw/lodsd
        Scas,           // scasb/scasw/scasd
        Cmps,           // cmpsb/cmpsw/cmpsd
        Rep,            // rep prefix (handled specially)
        // SSE instructions
        Movss,          // movss - move scalar single-precision float
        Movsd_sse,      // movsd - move scalar double-precision float (SSE, not string op)
        Movaps,         // movaps - move aligned packed single-precision floats
        Movups,         // movups - move unaligned packed single-precision floats
        Movapd,         // movapd - move aligned packed double-precision floats
        Movupd,         // movupd - move unaligned packed double-precision floats
        Addss,          // addss - add scalar single-precision float
        Addsd,          // addsd - add scalar double-precision float
        Subss,          // subss - subtract scalar single-precision float
        Subsd,          // subsd - subtract scalar double-precision float
        Mulss,          // mulss - multiply scalar single-precision float
        Mulsd,          // mulsd - multiply scalar double-precision float
        Divss,          // divss - divide scalar single-precision float
        Divsd,          // divsd - divide scalar double-precision float
        Sqrtss,         // sqrtss - square root scalar single-precision float
        Sqrtsd,         // sqrtsd - square root scalar double-precision float
        Rsqrtss,        // rsqrtss - reciprocal square root scalar single
        Rsqrtps,        // rsqrtps - reciprocal square root packed single
        Rcpss,          // rcpss - reciprocal scalar single
        Rcpps,          // rcpps - reciprocal packed single
        Minss,          // minss - minimum scalar single-precision float
        Minsd,          // minsd - minimum scalar double-precision float
        Maxss,          // maxss - maximum scalar single-precision float
        Maxsd,          // maxsd - maximum scalar double-precision float
        Cmpss,          // cmpss - compare scalar single-precision float
        Cmpsd_sse,      // cmpsd - compare scalar double-precision float
        Comiss,         // comiss - compare scalar ordered single-precision float
        Comisd,         // comisd - compare scalar ordered double-precision float
        Ucomiss,        // ucomiss - unordered compare scalar single-precision float
        Ucomisd,        // ucomisd - unordered compare scalar double-precision float
        Cvtss2sd,       // cvtss2sd - convert scalar single to scalar double
        Cvtsd2ss,       // cvtsd2ss - convert scalar double to scalar single
        Cvtsi2ss,       // cvtsi2ss - convert dword integer to scalar single
        Cvtsi2sd,       // cvtsi2sd - convert dword integer to scalar double
        Cvtss2si,       // cvtss2si - convert scalar single to dword integer
        Cvtsd2si,       // cvtsd2si - convert scalar double to dword integer
        Cvttss2si,      // cvttss2si - convert with truncation scalar single to dword integer
        Cvttsd2si,      // cvttsd2si - convert with truncation scalar double to dword integer
        // SSE packed instructions (operate on 4 floats or 2 doubles)
        Addps,          // addps - add packed single-precision floats
        Subps,          // subps - subtract packed single-precision floats
        Mulps,          // mulps - multiply packed single-precision floats
        Divps,          // divps - divide packed single-precision floats
        Sqrtps,         // sqrtps - square root packed single-precision floats
        Minps,          // minps - minimum packed single-precision floats
        Maxps,          // maxps - maximum packed single-precision floats
        Andps,          // andps - bitwise AND packed single-precision floats
        Andnps,         // andnps - bitwise AND NOT packed single-precision floats
        Orps,           // orps - bitwise OR packed single-precision floats
        Xorps,          // xorps - bitwise XOR packed single-precision floats
        Shufps,         // shufps - shuffle packed single-precision floats
        Unpcklps,       // unpcklps - unpack and interleave low packed single-precision floats
        Unpckhps,       // unpckhps - unpack and interleave high packed single-precision floats
        // Stack
        Pushad,         // pushad - push all registers
        Popad,          // popad - pop all registers
        Pushfd,         // pushfd - push flags
        Popfd,          // popfd - pop flags
        // Misc
        Xchg,           // xchg - exchange
        Cdq,            // cdq - sign extend eax into edx:eax
        Cwde,           // cwde - sign extend ax into eax
        Bswap,          // bswap - byte swap
        SetCC,          // setcc - set byte on condition
        Cmovcc,         // cmovcc - conditional move
        // FPU (basic operations)
        Fld,            // fld - load float (includes FLD1, FLDZ, FLDPI, etc.)
        Fst,            // fst/fstp - store float
        Fild,           // fild - load integer
        Fist,           // fist/fistp - store integer
        Fadd,           // fadd/faddp - float add
        Fsub,           // fsub/fsubp/fsubr/fsubrp - float subtract
        Fmul,           // fmul/fmulp - float multiply
        Fdiv,           // fdiv/fdivp/fdivr/fdivrp - float divide
        Fcom,           // fcom/fcomp/fcompp - float compare
        Fucom,          // fucom/fucomp/fucompp - unordered compare
        Fcomi,          // fcomi/fcomip/fucomi/fucomip - compare and set EFLAGS
        Fxch,           // fxch - exchange FPU registers
        Fchs,           // fchs - change sign
        Fabs,           // fabs - absolute value
        Ftst,           // ftst - test (compare with 0)
        Fxam,           // fxam - examine
        Fsqrt,          // fsqrt - square root
        Fsin,           // fsin - sine
        Fcos,           // fcos - cosine
        Fsincos,        // fsincos - sine and cosine
        Fptan,          // fptan - partial tangent
        Fpatan,         // fpatan - partial arctangent
        Fscale,         // fscale - scale by power of 2
        Frndint,        // frndint - round to integer
        F2xm1,          // f2xm1 - 2^x - 1
        Fyl2x,          // fyl2x - y * log2(x)
        Fyl2xp1,        // fyl2xp1 - y * log2(x+1)
        Fprem,          // fprem/fprem1 - partial remainder
        Fdecstp,        // fdecstp - decrement stack pointer
        Fincstp,        // fincstp - increment stack pointer
        Ffree,          // ffree - free FPU register
        Fldcw,          // fldcw - load control word
        Fstcw,          // fstcw/fnstcw - store control word
        Fstsw,          // fstsw/fnstsw - store status word
        Fldenv,         // fldenv - load FPU environment
        Fstenv,         // fstenv/fnstenv - store FPU environment
        Fsave,          // fsave/fnsave - save FPU state
        Frstor,         // frstor - restore FPU state
        Finit,          // finit/fninit - initialize FPU
        Fclex,          // fclex/fnclex - clear exceptions
        // MMX instructions
        Movd,           // movd - move doubleword to/from MMX
        Movq,           // movq - move quadword to/from MMX/XMM
        Emms,           // emms - empty MMX state
        Pand,           // pand - packed AND
        Pandn,          // pandn - packed AND NOT
        Por,            // por - packed OR
        Pxor,           // pxor - packed XOR
        // MMX packed compare
        Pcmpeqb,        // pcmpeqb - packed compare equal byte
        Pcmpeqw,        // pcmpeqw - packed compare equal word
        Pcmpeqd,        // pcmpeqd - packed compare equal dword
        Pcmpgtb,        // pcmpgtb - packed compare greater than byte
        Pcmpgtw,        // pcmpgtw - packed compare greater than word
        Pcmpgtd,        // pcmpgtd - packed compare greater than dword
        // MMX packed arithmetic
        Paddb,          // paddb - packed add byte
        Paddw,          // paddw - packed add word
        Paddd,          // paddd - packed add dword
        Psubb,          // psubb - packed subtract byte
        Psubw,          // psubw - packed subtract word
        Psubd,          // psubd - packed subtract dword
        Pmullw,         // pmullw - packed multiply low word
        Pmulhw,         // pmulhw - packed multiply high word
        Pmaddwd,        // pmaddwd - packed multiply and add
        // MMX unpack/pack
        Punpcklbw,      // punpcklbw - unpack low bytes to words
        Punpcklwd,      // punpcklwd - unpack low words to dwords
        Punpckldq,      // punpckldq - unpack low dwords to qwords
        Punpckhbw,      // punpckhbw - unpack high bytes to words
        Punpckhwd,      // punpckhwd - unpack high words to dwords
        Punpckhdq,      // punpckhdq - unpack high dwords to qwords
        Packsswb,       // packsswb - pack words to bytes with saturation
        Packssdw,       // packssdw - pack dwords to words with saturation
        Packuswb,       // packuswb - pack words to bytes unsigned with saturation
        // MMX shift
        Psrlw,          // psrlw - packed shift right logical word
        Psrld,          // psrld - packed shift right logical dword
        Psrlq,          // psrlq - packed shift right logical qword
        Psraw,          // psraw - packed shift right arithmetic word
        Psrad,          // psrad - packed shift right arithmetic dword
        Psllw,          // psllw - packed shift left logical word
        Pslld,          // pslld - packed shift left logical dword
        Psllq,          // psllq - packed shift left logical qword
        // SSE/MMX extensions
        Pshufw,         // pshufw - shuffle packed words
        Pavgb,          // pavgb - average packed bytes
        Pavgw,          // pavgw - average packed words
        Pminub,         // pminub - minimum packed unsigned bytes
        Pmaxub,         // pmaxub - maximum packed unsigned bytes
        Pminsw,         // pminsw - minimum packed signed words
        Pmaxsw,         // pmaxsw - maximum packed signed words
        Movntq,         // movntq - store quadword using non-temporal hint
        Movntps,        // movntps - store packed single using non-temporal hint
        Prefetch,       // prefetch - prefetch data hint
        // Misc
        Lahf,           // lahf - load AH from flags
        Sahf,           // sahf - store AH into flags
        Bound,          // bound - check array bounds
        Hlt,            // hlt - halt processor
        In,             // in - input from port
        Out,            // out - output to port
        Loop,           // loop/loope/loopne - loop control
        Aaa,            // aaa - ASCII adjust after addition
        Aas,            // aas - ASCII adjust after subtraction
        Das,            // das - decimal adjust after subtraction
        Daa,            // daa - decimal adjust after addition
        Retf,           // retf - far return
        MovSeg,         // mov sreg, r/m16 - move to segment register
        Clc,            // clc - clear carry flag
        Stc,            // stc - set carry flag
        Cld,            // cld - clear direction flag
        Std,            // std - set direction flag
        Cli,            // cli - clear interrupt flag
        Sti,            // sti - set interrupt flag
        Cmc,            // cmc - complement carry flag
        Ins,            // ins - input string from port
        Outs,           // outs - output string to port
        Fwait,          // fwait/wait - wait for FPU
        Jecxz,          // jecxz - jump if ECX is zero
        Aam,            // aam - ASCII adjust after multiply
        Aad,            // aad - ASCII adjust before divide
        Into,           // into - interrupt on overflow
        Movlps,         // movlps - move low packed single
        Movhps,         // movhps - move high packed single
        Movmskps,       // movmskps - extract sign mask from packed floats
        Cmpps,          // cmpps - compare packed single-precision floats
        Shld,           // shld - double precision shift left
        Shrd,           // shrd - double precision shift right
        Bsf,            // bsf - bit scan forward
        Bsr,            // bsr - bit scan reverse
        Rdtsc,          // rdtsc - read time stamp counter
        Xlat,           // xlat - table lookup translation
        Iret,           // iret - interrupt return
        Callf,          // callf - far call
        
        // Additional instructions
        Les,            // les - load far pointer using ES
        Lds,            // lds - load far pointer using DS
        Lss,            // lss - load far pointer using SS (0F B2)
        Lfs,            // lfs - load far pointer using FS (0F B4)
        Lgs,            // lgs - load far pointer using GS (0F B5)
        Arpl,           // arpl - adjust RPL field
        Salc,           // salc - set AL from carry (undocumented)
        Int1,           // int1/icebp - single-step interrupt
        Ud2,            // ud2 - undefined instruction (intentional trap)
        Cmpxchg,        // cmpxchg - compare and exchange
        Xadd,           // xadd - exchange and add
        Cvtps2pi,       // cvtps2pi - convert packed single to packed dword int
        Cvtpd2pi,       // cvtpd2pi - convert packed double to packed dword int
        Cvttps2pi,      // cvttps2pi - convert with truncation
        Cvttpd2pi,      // cvttpd2pi - convert with truncation
        Lar,            // lar - load access rights
        Sldt,           // sldt - store local descriptor table
        Str,            // str - store task register
        Lldt,           // lldt - load local descriptor table
        Ltr,            // ltr - load task register
        Verr,           // verr - verify segment for reading
        Verw,           // verw - verify segment for writing
        Jmpf,           // jmpf - far jump
        
        // Bit manipulation
        Bt,             // bt - bit test
        Bts,            // bts - bit test and set
        Btr,            // btr - bit test and reset
        Btc,            // btc - bit test and complement
        
        // Additional MMX/SSE
        Cvtpi2ps,       // cvtpi2ps - convert packed dword int to packed single
        Cvtpi2pd,       // cvtpi2pd - convert packed dword int to packed double
        Pinsrw,         // pinsrw - insert word
        Pextrw,         // pextrw - extract word
        Pmovmskb,       // pmovmskb - move byte mask
        
        // 3DNow!
        Amd3dnow,       // 3DNow! instructions (AMD)
        
        // System instructions
        Clts,           // clts - clear task-switched flag
        Sgdt,           // sgdt - store global descriptor table
        Sidt,           // sidt - store interrupt descriptor table
        Lgdt,           // lgdt - load global descriptor table
        Lidt,           // lidt - load interrupt descriptor table
        Smsw,           // smsw - store machine status word
        Lmsw,           // lmsw - load machine status word
        Invlpg,         // invlpg - invalidate TLB entry
        Ldmxcsr,        // ldmxcsr - load MXCSR register
        Stmxcsr,        // stmxcsr - store MXCSR register
        Fxsave,         // fxsave - save FPU/MMX/SSE state
        Fxrstor,        // fxrstor - restore FPU/MMX/SSE state
        Lfence,         // lfence - load fence
        Mfence,         // mfence - memory fence
        Sfence,         // sfence - store fence
        Cpuid,          // cpuid - CPU identification
        Wbinvd,         // wbinvd - write back and invalidate cache
        Invd,           // invd - invalidate cache
        Sysret,         // sysret - return from fast system call
        
        // SSE3 horizontal operations
        Haddps,         // haddps - horizontal add packed single
        Haddpd,         // haddpd - horizontal add packed double
        Hsubps,         // hsubps - horizontal subtract packed single
        Hsubpd,         // hsubpd - horizontal subtract packed double
        
        // SSE compare packed
        Cmppd,          // cmppd - compare packed double-precision floats
        
        // SSE2 move operations
        Movdqu,         // movdqu - move unaligned double quadword (F3 0F 6F/7F)
        Movq_sse,       // movq - move quadword SSE (F3 0F 7E, 66 0F D6)

        // Other
        Nop,            // nop
        Int3,           // int 3 (breakpoint/padding)
        Int,            // int n - software interrupt
        Invalid,        // invalid/unrecognized
    };

    // Condition codes for Jcc
    enum class Condition
    {
        None,
        O, NO, B, NB, E, NE, BE, A,
        S, NS, P, NP, L, GE, LE, G
    };

    // Operand types
    enum class OpType
    {
        None,
        Reg,
        Imm,
        Mem,            // [base + index*scale + disp]
        MemDisp,        // [disp32] - absolute memory reference (for jump tables)
    };

    // x86 registers
    enum Reg : uint8_t
    {
        EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
        // MMX registers (8-15)
        MM0 = 8, MM1, MM2, MM3, MM4, MM5, MM6, MM7,
        // XMM registers (16-23)
        XMM0 = 16, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
        X86_REG_NONE = 0xFF
    };

    struct Operand
    {
        OpType type = OpType::None;
        Reg reg = X86_REG_NONE;
        Reg base = X86_REG_NONE;
        Reg index = X86_REG_NONE;
        uint8_t scale = 1;
        int32_t disp = 0;
        uint32_t imm = 0;
    };

    struct Insn
    {
        uint32_t address = 0;
        uint8_t length = 0;
        uint8_t operandSize = 4;  // 1, 2, or 4 bytes
        InsnType type = InsnType::Unknown;
        Condition cond = Condition::None;
        Operand op[3];  // Some instructions like CMPSS/CMPSD have 3 operands
        
        // For branches, the target address
        uint32_t branch_target = 0;
        bool is_branch_relative = false;
        bool hasRepPrefix = false;  // REP/REPE/REPNE prefix
        
        // For FPU instructions (D8-DF): stores raw opcode and modrm for precise decoding
        uint8_t fpuOpcode = 0;      // The D8-DF opcode byte
        uint8_t fpuModrm = 0;       // The modrm byte following FPU opcode
        bool fpuPop = false;        // True if instruction pops stack (FSTP, FADDP, etc.)
        bool fpuReverse = false;    // True for reversed operands (FSUBR, FDIVR)
        bool fpuInteger = false;    // True for integer operations (FILD, FIST, etc.)
    };

    // Disassemble a single x86 instruction
    // Returns number of bytes consumed (0 on error)
    int Disassemble(const void* code, size_t maxLen, uint32_t address, Insn& out);

    // Check if instruction is a function prologue pattern
    bool IsFunctionPrologue(const Insn& insn);
    
    // Check if instruction is a return/function end
    bool IsFunctionEpilogue(const Insn& insn);
    
    // Check if instruction is an unconditional control transfer
    bool IsUnconditionalBranch(const Insn& insn);
    
    // Get register name string
    const char* GetRegName(Reg reg);
}
