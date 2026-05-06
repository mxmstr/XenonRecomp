#include "recompiler.h"
#include <xbe.h>
#include <file.h>
#include <section.h>
#include <fmt/core.h>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <xxhash.h>

// ---- Xbox kernel thunk table ----
static const std::unordered_map<uint32_t, const char*> XboxKernelNames = {
    { 1,   "AvGetSavedDataAddress" },
    { 2,   "AvSendTVEncoderOption" },
    { 3,   "AvSetDisplayMode" },
    { 4,   "AvSetSavedDataAddress" },
    { 14,  "DbgPrint" },
    { 24,  "ExAllocatePool" },
    { 25,  "ExAllocatePoolWithTag" },
    { 26,  "ExEventObjectType" },
    { 29,  "ExFreePool" },
    { 36,  "ExQueryPoolBlockSize" },
    { 49,  "HalReadSMCTrayState" },
    { 66,  "IoCreateDevice" },
    { 67,  "IoCreateSymbolicLink" },
    { 71,  "IoDeleteDevice" },
    { 72,  "IoDeleteSymbolicLink" },
    { 84,  "IoDismountVolumeByName" },
    { 95,  "KeAlertResumeThread" },
    { 107, "KeInitializeDpc" },
    { 113, "KeInitializeTimerEx" },
    { 120, "KeLeaveCriticalRegion" },
    { 128, "KeQueryPerformanceCounter" },
    { 129, "KeQueryPerformanceFrequency" },
    { 137, "KeResumeThread" },
    { 141, "KeSetEvent" },
    { 148, "KeSetTimer" },
    { 150, "KeStallExecutionProcessor" },
    { 152, "KeSuspendThread" },
    { 158, "KeTickCount" },
    { 160, "KeWaitForSingleObject" },
    { 165, "MmAllocateContiguousMemory" },
    { 166, "MmAllocateContiguousMemoryEx" },
    { 171, "MmFreeContiguousMemory" },
    { 178, "MmMapIoSpace" },
    { 184, "MmPersistContiguousMemory" },
    { 187, "MmQueryAllocationSize" },
    { 190, "MmSetAddressProtect" },
    { 195, "NtAllocateVirtualMemory" },
    { 197, "NtClose" },
    { 199, "NtCreateEvent" },
    { 200, "NtCreateFile" },
    { 202, "NtCreateMutant" },
    { 204, "NtCreateSemaphore" },
    { 211, "NtFlushBuffersFile" },
    { 214, "NtFreeVirtualMemory" },
    { 217, "NtOpenFile" },
    { 218, "NtOpenSymbolicLinkObject" },
    { 219, "NtProtectVirtualMemory" },
    { 221, "NtQueryDirectoryFile" },
    { 226, "NtQueryInformationFile" },
    { 228, "NtQuerySymbolicLinkObject" },
    { 229, "NtQueryVirtualMemory" },
    { 230, "NtQueryVolumeInformationFile" },
    { 232, "NtReadFile" },
    { 233, "NtReadFileScatter" },
    { 236, "NtResumeThread" },
    { 237, "NtSetEvent" },
    { 238, "NtSetInformationFile" },
    { 240, "NtSetSystemTime" },
    { 254, "NtWriteFile" },
    { 255, "NtWriteFileGather" },
    { 258, "ObDereferenceObject" },
    { 259, "ObOpenObjectByName" },
    { 260, "ObOpenObjectByPointer" },
    { 261, "ObpObjectHandleTable" },
    { 262, "ObReferenceObjectByHandle" },
    { 263, "ObReferenceObjectByName" },
    { 275, "PsCreateSystemThreadEx" },
    { 295, "RtlAnsiStringToUnicodeString" },
    { 299, "RtlCopyString" },
    { 300, "RtlCopyUnicodeString" },
    { 302, "RtlEnterCriticalSection" },
    { 305, "RtlFreeAnsiString" },
    { 306, "RtlFreeUnicodeString" },
    { 309, "RtlInitAnsiString" },
    { 312, "RtlInitUnicodeString" },
    { 314, "RtlLeaveCriticalSection" },
    { 320, "RtlNtStatusToDosError" },
    { 327, "RtlUnicodeStringToAnsiString" },
    { 329, "XeImageFileName" },
    { 334, "XboxHardwareInfo" },
    { 335, "XboxHDKey" },
    { 336, "XboxKrnlVersion" },
    { 340, "XePublicKeyData" },
    { 344, "HalBootSMCVideoMode" },
};

// ---- Helper: Zydis register to C struct field name ----
const char* XBERecompiler::RegName(ZydisRegister reg)
{
    switch (reg)
    {
    case ZYDIS_REGISTER_EAX: return "eax";
    case ZYDIS_REGISTER_ECX: return "ecx";
    case ZYDIS_REGISTER_EDX: return "edx";
    case ZYDIS_REGISTER_EBX: return "ebx";
    case ZYDIS_REGISTER_ESP: return "esp";
    case ZYDIS_REGISTER_EBP: return "ebp";
    case ZYDIS_REGISTER_ESI: return "esi";
    case ZYDIS_REGISTER_EDI: return "edi";
    case ZYDIS_REGISTER_AX: return "ax";
    case ZYDIS_REGISTER_CX: return "cx";
    case ZYDIS_REGISTER_DX: return "dx";
    case ZYDIS_REGISTER_BX: return "bx";
    case ZYDIS_REGISTER_SP: return "sp";
    case ZYDIS_REGISTER_BP: return "bp";
    case ZYDIS_REGISTER_SI: return "si";
    case ZYDIS_REGISTER_DI: return "di";
    case ZYDIS_REGISTER_AL: return "al";
    case ZYDIS_REGISTER_CL: return "cl";
    case ZYDIS_REGISTER_DL: return "dl";
    case ZYDIS_REGISTER_BL: return "bl";
    case ZYDIS_REGISTER_AH: return "ah";
    case ZYDIS_REGISTER_CH: return "ch";
    case ZYDIS_REGISTER_DH: return "dh";
    case ZYDIS_REGISTER_BH: return "bh";
    case ZYDIS_REGISTER_XMM0: return "xmm0";
    case ZYDIS_REGISTER_XMM1: return "xmm1";
    case ZYDIS_REGISTER_XMM2: return "xmm2";
    case ZYDIS_REGISTER_XMM3: return "xmm3";
    case ZYDIS_REGISTER_XMM4: return "xmm4";
    case ZYDIS_REGISTER_XMM5: return "xmm5";
    case ZYDIS_REGISTER_XMM6: return "xmm6";
    case ZYDIS_REGISTER_XMM7: return "xmm7";
    case ZYDIS_REGISTER_MM0: return "mm0";
    case ZYDIS_REGISTER_MM1: return "mm1";
    case ZYDIS_REGISTER_MM2: return "mm2";
    case ZYDIS_REGISTER_MM3: return "mm3";
    case ZYDIS_REGISTER_MM4: return "mm4";
    case ZYDIS_REGISTER_MM5: return "mm5";
    case ZYDIS_REGISTER_MM6: return "mm6";
    case ZYDIS_REGISTER_MM7: return "mm7";
    default: return "UNKNOWN_REG";
    }
}

// ---- Helper: format a context register access ----
static std::string CtxReg(ZydisRegister reg)
{
    switch (reg)
    {
    case ZYDIS_REGISTER_EAX: return "ctx.eax";
    case ZYDIS_REGISTER_ECX: return "ctx.ecx";
    case ZYDIS_REGISTER_EDX: return "ctx.edx";
    case ZYDIS_REGISTER_EBX: return "ctx.ebx";
    case ZYDIS_REGISTER_ESP: return "ctx.esp";
    case ZYDIS_REGISTER_EBP: return "ctx.ebp";
    case ZYDIS_REGISTER_ESI: return "ctx.esi";
    case ZYDIS_REGISTER_EDI: return "ctx.edi";
    case ZYDIS_REGISTER_AX:  return "X86_REG16(ctx.eax)";
    case ZYDIS_REGISTER_CX:  return "X86_REG16(ctx.ecx)";
    case ZYDIS_REGISTER_DX:  return "X86_REG16(ctx.edx)";
    case ZYDIS_REGISTER_BX:  return "X86_REG16(ctx.ebx)";
    case ZYDIS_REGISTER_SP:  return "X86_REG16(ctx.esp)";
    case ZYDIS_REGISTER_BP:  return "X86_REG16(ctx.ebp)";
    case ZYDIS_REGISTER_SI:  return "X86_REG16(ctx.esi)";
    case ZYDIS_REGISTER_DI:  return "X86_REG16(ctx.edi)";
    case ZYDIS_REGISTER_AL:  return "X86_REG8L(ctx.eax)";
    case ZYDIS_REGISTER_CL:  return "X86_REG8L(ctx.ecx)";
    case ZYDIS_REGISTER_DL:  return "X86_REG8L(ctx.edx)";
    case ZYDIS_REGISTER_BL:  return "X86_REG8L(ctx.ebx)";
    case ZYDIS_REGISTER_AH:  return "X86_REG8H(ctx.eax)";
    case ZYDIS_REGISTER_CH:  return "X86_REG8H(ctx.ecx)";
    case ZYDIS_REGISTER_DH:  return "X86_REG8H(ctx.edx)";
    case ZYDIS_REGISTER_BH:  return "X86_REG8H(ctx.ebx)";
    case ZYDIS_REGISTER_MM0: return "ctx.mm[0].u64";
    case ZYDIS_REGISTER_MM1: return "ctx.mm[1].u64";
    case ZYDIS_REGISTER_MM2: return "ctx.mm[2].u64";
    case ZYDIS_REGISTER_MM3: return "ctx.mm[3].u64";
    case ZYDIS_REGISTER_MM4: return "ctx.mm[4].u64";
    case ZYDIS_REGISTER_MM5: return "ctx.mm[5].u64";
    case ZYDIS_REGISTER_MM6: return "ctx.mm[6].u64";
    case ZYDIS_REGISTER_MM7: return "ctx.mm[7].u64";
    default: return fmt::format("ctx.{}", XBERecompiler::RegName(reg));
    }
}

static const char* MemSuffix(int bits)
{
    switch (bits)
    {
    case 8:  return "u8";
    case 16: return "u16";
    case 32: return "u32";
    case 64: return "u64";
    default: return "u32";
    }
}

static const char* SignedType(int bits)
{
    switch (bits)
    {
    case 8:  return "int8_t";
    case 16: return "int16_t";
    case 32: return "int32_t";
    default: return "int32_t";
    }
}

static const char* UnsignedType(int bits)
{
    switch (bits)
    {
    case 8:  return "uint8_t";
    case 16: return "uint16_t";
    case 32: return "uint32_t";
    case 64: return "uint64_t";
    default: return "uint32_t";
    }
}

void XBERecompiler::print(const std::string& s)
{
    tempOut += s;
}

void XBERecompiler::println(const std::string& s)
{
    tempOut += s;
    tempOut += '\n';
}

// Format a memory operand into a C expression for the effective address
std::string XBERecompiler::FormatMemOperand(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand& op,
    uint32_t address)
{
    std::string result;
    bool hasBase = op.mem.base != ZYDIS_REGISTER_NONE;
    bool hasIndex = op.mem.index != ZYDIS_REGISTER_NONE;
    bool hasDisp = op.mem.disp.has_displacement && op.mem.disp.value != 0;

    if (!hasBase && !hasIndex)
    {
        return fmt::format("0x{:X}u", static_cast<uint32_t>(op.mem.disp.value));
    }

    if (hasBase)
        result = CtxReg(op.mem.base);

    if (hasIndex)
    {
        if (!result.empty()) result += " + ";
        result += CtxReg(op.mem.index);
        if (op.mem.scale > 1)
            result += fmt::format(" * {}", op.mem.scale);
    }

    if (hasDisp)
    {
        int64_t d = op.mem.disp.value;
        if (d >= 0)
            result += fmt::format(" + 0x{:X}u", static_cast<uint32_t>(d));
        else
            result += fmt::format(" - 0x{:X}u", static_cast<uint32_t>(-d));
    }

    return result;
}

// Format an operand to a C expression
std::string XBERecompiler::FormatOperand(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand& op,
    uint32_t address)
{
    switch (op.type)
    {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        return CtxReg(op.reg.value);

    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        if (op.imm.is_signed)
            return fmt::format("{}", static_cast<int32_t>(op.imm.value.s));
        else
            return fmt::format("0x{:X}u", static_cast<uint32_t>(op.imm.value.u));

    case ZYDIS_OPERAND_TYPE_MEMORY:
    {
        std::string ea = FormatMemOperand(insn, op, address);
        int bits = op.size;
        return fmt::format("X86_MEM_READ_{}(base, {})", MemSuffix(bits), ea);
    }

    default:
        return "/* unknown operand */";
    }
}

// ---- Condition code helpers ----
const char* XBERecompiler::FlagsCondition(ZydisMnemonic mnemonic)
{
    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_JO:    return "ctx.flags.of";
    case ZYDIS_MNEMONIC_JNO:   return "!ctx.flags.of";
    case ZYDIS_MNEMONIC_JB:    return "ctx.flags.cf";
    case ZYDIS_MNEMONIC_JNB:   return "!ctx.flags.cf";
    case ZYDIS_MNEMONIC_JZ:    return "ctx.flags.zf";
    case ZYDIS_MNEMONIC_JNZ:   return "!ctx.flags.zf";
    case ZYDIS_MNEMONIC_JBE:   return "(ctx.flags.cf || ctx.flags.zf)";
    case ZYDIS_MNEMONIC_JNBE:  return "(!ctx.flags.cf && !ctx.flags.zf)";
    case ZYDIS_MNEMONIC_JS:    return "ctx.flags.sf";
    case ZYDIS_MNEMONIC_JNS:   return "!ctx.flags.sf";
    case ZYDIS_MNEMONIC_JP:    return "ctx.flags.pf";
    case ZYDIS_MNEMONIC_JNP:   return "!ctx.flags.pf";
    case ZYDIS_MNEMONIC_JL:    return "(ctx.flags.sf != ctx.flags.of)";
    case ZYDIS_MNEMONIC_JNL:   return "(ctx.flags.sf == ctx.flags.of)";
    case ZYDIS_MNEMONIC_JLE:   return "(ctx.flags.zf || ctx.flags.sf != ctx.flags.of)";
    case ZYDIS_MNEMONIC_JNLE:  return "(!ctx.flags.zf && ctx.flags.sf == ctx.flags.of)";
    default: return "/* unknown condition */";
    }
}

static const char* CMovSetCondition(ZydisMnemonic mnemonic)
{
    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_CMOVO:  case ZYDIS_MNEMONIC_SETO:  return "ctx.flags.of";
    case ZYDIS_MNEMONIC_CMOVNO: case ZYDIS_MNEMONIC_SETNO: return "!ctx.flags.of";
    case ZYDIS_MNEMONIC_CMOVB:  case ZYDIS_MNEMONIC_SETB:  return "ctx.flags.cf";
    case ZYDIS_MNEMONIC_CMOVNB: case ZYDIS_MNEMONIC_SETNB: return "!ctx.flags.cf";
    case ZYDIS_MNEMONIC_CMOVZ:  case ZYDIS_MNEMONIC_SETZ:  return "ctx.flags.zf";
    case ZYDIS_MNEMONIC_CMOVNZ: case ZYDIS_MNEMONIC_SETNZ: return "!ctx.flags.zf";
    case ZYDIS_MNEMONIC_CMOVBE: case ZYDIS_MNEMONIC_SETBE: return "(ctx.flags.cf || ctx.flags.zf)";
    case ZYDIS_MNEMONIC_CMOVNBE:case ZYDIS_MNEMONIC_SETNBE:return "(!ctx.flags.cf && !ctx.flags.zf)";
    case ZYDIS_MNEMONIC_CMOVS:  case ZYDIS_MNEMONIC_SETS:  return "ctx.flags.sf";
    case ZYDIS_MNEMONIC_CMOVNS: case ZYDIS_MNEMONIC_SETNS: return "!ctx.flags.sf";
    case ZYDIS_MNEMONIC_CMOVP:  case ZYDIS_MNEMONIC_SETP:  return "ctx.flags.pf";
    case ZYDIS_MNEMONIC_CMOVNP: case ZYDIS_MNEMONIC_SETNP: return "!ctx.flags.pf";
    case ZYDIS_MNEMONIC_CMOVL:  case ZYDIS_MNEMONIC_SETL:  return "(ctx.flags.sf != ctx.flags.of)";
    case ZYDIS_MNEMONIC_CMOVNL: case ZYDIS_MNEMONIC_SETNL: return "(ctx.flags.sf == ctx.flags.of)";
    case ZYDIS_MNEMONIC_CMOVLE: case ZYDIS_MNEMONIC_SETLE: return "(ctx.flags.zf || ctx.flags.sf != ctx.flags.of)";
    case ZYDIS_MNEMONIC_CMOVNLE:case ZYDIS_MNEMONIC_SETNLE:return "(!ctx.flags.zf && ctx.flags.sf == ctx.flags.of)";
    default: return "/* unknown condition */";
    }
}

// =====================================================================
// LoadConfig / LoadXBE / HookKernelImports
// =====================================================================

bool XBERecompiler::LoadConfig(const std::string_view& configFilePath)
{
    config.Load(configFilePath);
    return !config.filePath.empty();
}

bool XBERecompiler::LoadXBE()
{
    std::string fullPath = config.directoryPath + config.filePath;
    auto file = LoadFile(fullPath.c_str());
    if (file.empty())
    {
        fmt::println("ERROR: Failed to load XBE file: {}", fullPath);
        return false;
    }

    if (file.size() < sizeof(XbeImageHeader) || memcmp(file.data(), "XBEH", 4) != 0)
    {
        fmt::println("ERROR: Not a valid XBE file: {}", fullPath);
        return false;
    }

    const auto* header = reinterpret_cast<const XbeImageHeader*>(file.data());
    kernelThunkAddr = header->kernelThunkAddress ^ XBE_KERNEL_THUNK_RETAIL_XOR;
    if (kernelThunkAddr < header->baseAddress || kernelThunkAddr >= header->baseAddress + header->sizeOfImage)
    {
        kernelThunkAddr = header->kernelThunkAddress ^ XBE_KERNEL_THUNK_DEBUG_XOR;
    }

    image = XbeLoadImage(file.data(), file.size());
    if (image.sections.empty())
    {
        fmt::println("ERROR: Failed to parse XBE image");
        return false;
    }

    // Add functions from config as symbols
    for (auto& [address, funcData] : config.functions)
    {
        image.symbols.emplace(Symbol{
            fmt::format("sub_{:X}", address), address, funcData.size, Symbol_Function });
    }

    fmt::println("Loaded XBE: base=0x{:X} size=0x{:X} entry=0x{:X}", image.base, image.size, image.entry_point);
    fmt::println("Kernel thunk table at: 0x{:X}", kernelThunkAddr);
    fmt::println("Loaded {} functions from config", config.functions.size());

    // Initialize Zydis decoder for 32-bit x86
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    return true;
}

bool XBERecompiler::HookKernelImports()
{
    if (kernelThunkAddr == 0)
    {
        fmt::println("WARNING: No kernel thunk table found");
        return true;
    }

    const uint8_t* thunkData = static_cast<const uint8_t*>(image.Find(kernelThunkAddr));
    if (!thunkData)
    {
        fmt::println("WARNING: Could not find kernel thunk table in image");
        return true;
    }

    uint32_t thunkAddr = kernelThunkAddr;
    const uint32_t* thunks = reinterpret_cast<const uint32_t*>(thunkData);

    for (size_t i = 0; thunks[i] != 0; i++, thunkAddr += 4)
    {
        uint32_t thunkValue = thunks[i];
        if (!(thunkValue & 0x80000000))
            continue;

        uint32_t ordinal = thunkValue & 0xFFFF;
        auto nameIt = XboxKernelNames.find(ordinal);
        const char* name = nameIt != XboxKernelNames.end() ? nameIt->second : "UnknownKernelExport";

        hookedImports[thunkAddr] = name;
    }

    fmt::println("Identified {} kernel imports", hookedImports.size());
    return true;
}

// =====================================================================
// Analyse
// =====================================================================

void XBERecompiler::Analyse()
{
    auto entry = image.symbols.find(image.entry_point);
    if (entry == image.symbols.end())
    {
        image.symbols.emplace(Symbol{
            "_xstart", image.entry_point, 0, Symbol_Function });
    }
    else
    {
        entry->name = "_xstart";
    }
}

// =====================================================================
// Helper: check if address belongs to current function's regions
// =====================================================================

bool XBERecompiler::IsLocalAddress(uint32_t addr) const
{
    // Must not be another function's entry point (unless it's our own entry)
    if (config.functions.count(addr) && addr != curFuncBase)
        return false;
    for (auto& r : funcRegions)
    {
        if (addr >= r.address && addr < r.address + r.size)
            return true;
    }
    return false;
}

// =====================================================================
// Per-instruction recompilation
// =====================================================================

bool XBERecompiler::RecompileInstruction(
    uint32_t address,
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand* operands,
    const std::unordered_map<uint32_t, XBERecompSwitchTable>::iterator& switchTable)
{
    char disasmBuf[256];
    ZydisFormatterFormatInstruction(&formatter, &insn, operands,
        insn.operand_count, disasmBuf, sizeof(disasmBuf), address, nullptr);
    println(fmt::format("\t// 0x{:X}: {}", address, disasmBuf));

    auto dst = [&]() -> std::string {
        return FormatOperand(insn, operands[0], address);
    };
    auto src = [&]() -> std::string {
        return FormatOperand(insn, operands[1], address);
    };
    auto src2 = [&]() -> std::string {
        return FormatOperand(insn, operands[2], address);
    };

    auto dstWrite = [&](const std::string& value) -> std::string {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            std::string ea = FormatMemOperand(insn, operands[0], address);
            return fmt::format("X86_MEM_WRITE_{}(base, {}, {})",
                MemSuffix(operands[0].size), ea, value);
        }
        return fmt::format("{} = {}", dst(), value);
    };

    int opSize = operands[0].size;
    auto utype = [&]() { return UnsignedType(opSize); };
    auto stype = [&]() { return SignedType(opSize); };

    auto emitLogicFlags = [&](const std::string& result, int bits) {
        println(fmt::format("\tX86_UPDATE_FLAGS_LOGIC(ctx, {}, {});", result, bits));
    };

    switch (insn.mnemonic)
    {
    // ---- Data movement ----
    case ZYDIS_MNEMONIC_MOV:
    {
        std::string val = src();
        if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && opSize < 32 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            val = fmt::format("({})({})", utype(), val);
        println(fmt::format("\t{};", dstWrite(val)));
        break;
    }

    case ZYDIS_MNEMONIC_MOVZX:
        println(fmt::format("\t{} = ({})({});", dst(), utype(), src()));
        break;

    case ZYDIS_MNEMONIC_MOVSX:
        println(fmt::format("\t{} = ({})(({})({}));", dst(), utype(), SignedType(operands[1].size), src()));
        break;

    case ZYDIS_MNEMONIC_LEA:
        println(fmt::format("\t{} = {};", dst(), FormatMemOperand(insn, operands[1], address)));
        break;

    case ZYDIS_MNEMONIC_XCHG:
        if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            println(fmt::format("\t{{ auto _tmp = {}; {}; {} = _tmp; }}", dst(), dstWrite(src()), src()));
        else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            println(fmt::format("\t{{ auto _tmp = {}; {} = {}; {}; }}", src(), src(), dst(), dstWrite("_tmp")));
        else
            println(fmt::format("\t{{ auto _tmp = {}; {} = {}; {} = _tmp; }}", dst(), dst(), src(), src()));
        break;

    case ZYDIS_MNEMONIC_PUSH:
        println(fmt::format("\t{{ auto _pv = (uint32_t)({}); ctx.esp -= 4; X86_MEM_WRITE_u32(base, ctx.esp, _pv); }}", FormatOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_POP:
        println(fmt::format("\t{};", dstWrite("X86_MEM_READ_u32(base, ctx.esp)")));
        println(fmt::format("\tctx.esp += 4;"));
        break;

    case ZYDIS_MNEMONIC_CDQ:
        println("\tctx.edx = ((int32_t)ctx.eax < 0) ? 0xFFFFFFFF : 0;");
        break;

    case ZYDIS_MNEMONIC_CBW:
        println("\tX86_REG16(ctx.eax) = (uint16_t)(int16_t)(int8_t)X86_REG8L(ctx.eax);");
        break;

    case ZYDIS_MNEMONIC_CWDE:
        println("\tctx.eax = (uint32_t)(int32_t)(int16_t)X86_REG16(ctx.eax);");
        break;

    // ---- Arithmetic ----
    case ZYDIS_MNEMONIC_ADD:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ uint64_t _res = (uint64_t)({})({}) + (uint64_t)({})({});", utype(), d, utype(), s));
        println(fmt::format("\t  X86_UPDATE_FLAGS_ADD(ctx, _res, ({}){}, ({}){}, {});", stype(), d, stype(), s, opSize));
        println(fmt::format("\t  {}; }}", dstWrite(fmt::format("({}){}", utype(), "_res"))));
        break;
    }

    case ZYDIS_MNEMONIC_ADC:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ uint64_t _res = (uint64_t)({})({}) + (uint64_t)({})({}) + (uint64_t)ctx.flags.cf;", utype(), d, utype(), s));
        println(fmt::format("\t  X86_UPDATE_FLAGS_ADD(ctx, _res, ({}){}, ({}){}, {});", stype(), d, stype(), s, opSize));
        println(fmt::format("\t  {}; }}", dstWrite(fmt::format("({}){}", utype(), "_res"))));
        break;
    }

    case ZYDIS_MNEMONIC_SUB:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ {} _d = {}; {} _s = {};", utype(), d, utype(), s));
        println(fmt::format("\t  uint64_t _res = (uint64_t)_d - (uint64_t)_s;"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_SUB(ctx, _res, ({}){}, ({}){}, {});", stype(), "_d", stype(), "_s", opSize));
        println(fmt::format("\t  {}; }}", dstWrite(fmt::format("({}){}", utype(), "_res"))));
        break;
    }

    case ZYDIS_MNEMONIC_SBB:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ {} _d = {}; {} _s = {};", utype(), d, utype(), s));
        println(fmt::format("\t  uint64_t _res = (uint64_t)_d - (uint64_t)_s - (uint64_t)ctx.flags.cf;"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_SUB(ctx, _res, ({}){}, ({}){}, {});", stype(), "_d", stype(), "_s", opSize));
        println(fmt::format("\t  {}; }}", dstWrite(fmt::format("({}){}", utype(), "_res"))));
        break;
    }

    case ZYDIS_MNEMONIC_CMP:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ {} _d = {}; {} _s = {};", utype(), d, utype(), s));
        println(fmt::format("\t  uint64_t _res = (uint64_t)_d - (uint64_t)_s;"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_SUB(ctx, _res, ({}){}, ({}){}, {}); }}", stype(), "_d", stype(), "_s", opSize));
        break;
    }

    case ZYDIS_MNEMONIC_INC:
    {
        std::string d = dst();
        println(fmt::format("\t{{ {} _d = {};", utype(), d));
        println(fmt::format("\t  uint64_t _res = (uint64_t)_d + 1;"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_INC(ctx, _res, ({}){}, {});", stype(), "_d", opSize));
        println(fmt::format("\t  {}; }}", dstWrite(fmt::format("({}){}", utype(), "_res"))));
        break;
    }

    case ZYDIS_MNEMONIC_DEC:
    {
        std::string d = dst();
        println(fmt::format("\t{{ {} _d = {};", utype(), d));
        println(fmt::format("\t  uint64_t _res = (uint64_t)_d - 1;"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_DEC(ctx, _res, ({}){}, {});", stype(), "_d", opSize));
        println(fmt::format("\t  {}; }}", dstWrite(fmt::format("({}){}", utype(), "_res"))));
        break;
    }

    case ZYDIS_MNEMONIC_NEG:
    {
        std::string d = dst();
        println(fmt::format("\t{{ {} _d = {};", utype(), d));
        println(fmt::format("\t  {} _res = 0 - _d;", utype()));
        println(fmt::format("\t  X86_UPDATE_FLAGS_SUB(ctx, (uint64_t)_res, ({}){}, ({}){}, {});", stype(), "0", stype(), "_d", opSize));
        println(fmt::format("\t  ctx.flags.cf = (_d != 0);"));
        println(fmt::format("\t  {}; }}", dstWrite("_res")));
        break;
    }

    case ZYDIS_MNEMONIC_MUL:
    {
        if (opSize == 32)
        {
            println(fmt::format("\t{{ uint64_t _res = (uint64_t)ctx.eax * (uint64_t){};", dst()));
            println("\t  ctx.eax = (uint32_t)_res; ctx.edx = (uint32_t)(_res >> 32);");
            println("\t  ctx.flags.cf = ctx.flags.of = (ctx.edx != 0); }");
        }
        else if (opSize == 16)
        {
            println(fmt::format("\t{{ uint32_t _res = (uint32_t)X86_REG16(ctx.eax) * (uint32_t){};", dst()));
            println("\t  X86_REG16(ctx.eax) = (uint16_t)_res; X86_REG16(ctx.edx) = (uint16_t)(_res >> 16);");
            println("\t  ctx.flags.cf = ctx.flags.of = (X86_REG16(ctx.edx) != 0); }");
        }
        else
        {
            println(fmt::format("\t{{ uint16_t _res = (uint16_t)X86_REG8L(ctx.eax) * (uint16_t){};", dst()));
            println("\t  X86_REG16(ctx.eax) = _res;");
            println("\t  ctx.flags.cf = ctx.flags.of = (X86_REG8H(ctx.eax) != 0); }");
        }
        break;
    }

    case ZYDIS_MNEMONIC_IMUL:
    {
        if (insn.operand_count_visible == 1)
        {
            if (opSize == 32)
            {
                println(fmt::format("\t{{ int64_t _res = (int64_t)(int32_t)ctx.eax * (int64_t)(int32_t){};", dst()));
                println("\t  ctx.eax = (uint32_t)_res; ctx.edx = (uint32_t)((uint64_t)_res >> 32);");
                println("\t  ctx.flags.cf = ctx.flags.of = (_res != (int32_t)_res); }");
            }
        }
        else if (insn.operand_count_visible == 2)
        {
            println(fmt::format("\t{{ int64_t _res = (int64_t)({}){} * (int64_t)({}){};", stype(), dst(), stype(), src()));
            println(fmt::format("\t  {} = ({})_res;", dst(), utype()));
            println(fmt::format("\t  ctx.flags.cf = ctx.flags.of = (_res != ({})_res); }}", stype()));
        }
        else
        {
            println(fmt::format("\t{{ int64_t _res = (int64_t)({}){} * (int64_t)({}){};", stype(), src(), stype(), src2()));
            println(fmt::format("\t  {} = ({})_res;", dst(), utype()));
            println(fmt::format("\t  ctx.flags.cf = ctx.flags.of = (_res != ({})_res); }}", stype()));
        }
        break;
    }

    case ZYDIS_MNEMONIC_DIV:
    {
        if (opSize == 32)
        {
            println("\t{ uint64_t _dividend = ((uint64_t)ctx.edx << 32) | ctx.eax;");
            println(fmt::format("\t  uint32_t _divisor = {};", dst()));
            println("\t  ctx.eax = (uint32_t)(_dividend / _divisor);");
            println("\t  ctx.edx = (uint32_t)(_dividend % _divisor); }");
        }
        break;
    }

    case ZYDIS_MNEMONIC_IDIV:
    {
        if (opSize == 32)
        {
            println("\t{ int64_t _dividend = (int64_t)(((uint64_t)ctx.edx << 32) | ctx.eax);");
            println(fmt::format("\t  int32_t _divisor = (int32_t){};", dst()));
            println("\t  ctx.eax = (uint32_t)(int32_t)(_dividend / _divisor);");
            println("\t  ctx.edx = (uint32_t)(int32_t)(_dividend % _divisor); }");
        }
        break;
    }

    // ---- Logical ----
    case ZYDIS_MNEMONIC_AND:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{};", dstWrite(fmt::format("{} & {}", d, s))));
        emitLogicFlags(dst(), opSize);
        break;
    }

    case ZYDIS_MNEMONIC_OR:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{};", dstWrite(fmt::format("{} | {}", d, s))));
        emitLogicFlags(dst(), opSize);
        break;
    }

    case ZYDIS_MNEMONIC_XOR:
    {
        std::string d = dst(), s = src();
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[0].reg.value == operands[1].reg.value)
        {
            println(fmt::format("\t{} = 0;", d));
            println(fmt::format("\tX86_UPDATE_FLAGS_LOGIC(ctx, 0, {});", opSize));
        }
        else
        {
            println(fmt::format("\t{};", dstWrite(fmt::format("{} ^ {}", d, s))));
            emitLogicFlags(dst(), opSize);
        }
        break;
    }

    case ZYDIS_MNEMONIC_NOT:
        println(fmt::format("\t{};", dstWrite(fmt::format("~{}", dst()))));
        break;

    case ZYDIS_MNEMONIC_TEST:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\tX86_UPDATE_FLAGS_LOGIC(ctx, ({}) {} & {}, {});", utype(), d, s, opSize));
        break;
    }

    // ---- Shifts ----
    case ZYDIS_MNEMONIC_SHL:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F; if (_cnt) {{", s));
        println(fmt::format("\t  ctx.flags.cf = ({} >> ({} - _cnt)) & 1;", d, opSize));
        println(fmt::format("\t  {}", dstWrite(fmt::format("{} << _cnt", d)) + ";"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_LOGIC(ctx, {}, {}); }} }}", dst(), opSize));
        break;
    }

    case ZYDIS_MNEMONIC_SHR:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F; if (_cnt) {{", s));
        println(fmt::format("\t  ctx.flags.cf = ({} >> (_cnt - 1)) & 1;", d));
        println(fmt::format("\t  {}", dstWrite(fmt::format("({})({}) >> _cnt", utype(), d)) + ";"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_LOGIC(ctx, {}, {}); }} }}", dst(), opSize));
        break;
    }

    case ZYDIS_MNEMONIC_SAR:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F; if (_cnt) {{", s));
        println(fmt::format("\t  ctx.flags.cf = (({}){} >> (_cnt - 1)) & 1;", stype(), d));
        println(fmt::format("\t  {}", dstWrite(fmt::format("({})(({}){} >> _cnt)", utype(), stype(), d)) + ";"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_LOGIC(ctx, {}, {}); }} }}", dst(), opSize));
        break;
    }

    case ZYDIS_MNEMONIC_ROL:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F; if (_cnt) {{", s));
        println(fmt::format("\t  {}", dstWrite(fmt::format("({0} << _cnt) | ({0} >> ({1} - _cnt))", d, opSize)) + ";"));
        println(fmt::format("\t  ctx.flags.cf = {} & 1; }} }}", dst()));
        break;
    }

    case ZYDIS_MNEMONIC_ROR:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F; if (_cnt) {{", s));
        println(fmt::format("\t  {}", dstWrite(fmt::format("({0} >> _cnt) | ({0} << ({1} - _cnt))", d, opSize)) + ";"));
        println(fmt::format("\t  ctx.flags.cf = ({} >> {}) & 1; }} }}", dst(), opSize - 1));
        break;
    }

    case ZYDIS_MNEMONIC_SHLD:
    {
        std::string d = dst(), s = src(), cnt = src2();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F; if (_cnt) {{", cnt));
        println(fmt::format("\t  {}", dstWrite(fmt::format("({0} << _cnt) | (({1}) >> ({2} - _cnt))", d, s, opSize)) + ";"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_LOGIC(ctx, {}, {}); }} }}", dst(), opSize));
        break;
    }

    case ZYDIS_MNEMONIC_SHRD:
    {
        std::string d = dst(), s = src(), cnt = src2();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F; if (_cnt) {{", cnt));
        println(fmt::format("\t  {}", dstWrite(fmt::format("({0} >> _cnt) | (({1}) << ({2} - _cnt))", d, s, opSize)) + ";"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_LOGIC(ctx, {}, {}); }} }}", dst(), opSize));
        break;
    }

    case ZYDIS_MNEMONIC_BSF:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ {} _s = {};", utype(), s));
        println(fmt::format("\t  ctx.flags.zf = (_s == 0);"));
        println(fmt::format("\t  if (_s) {} = X86_BSF({}, _s); }}", d, opSize));
        break;
    }

    case ZYDIS_MNEMONIC_BSR:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ {} _s = {};", utype(), s));
        println(fmt::format("\t  ctx.flags.zf = (_s == 0);"));
        println(fmt::format("\t  if (_s) {} = X86_BSR({}, _s); }}", d, opSize));
        break;
    }

    case ZYDIS_MNEMONIC_BT:
        println(fmt::format("\tctx.flags.cf = ({} >> ({} & {})) & 1;", dst(), src(), opSize - 1));
        break;

    case ZYDIS_MNEMONIC_BTS:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _bit = {} & {};", s, opSize - 1));
        println(fmt::format("\t  ctx.flags.cf = ({} >> _bit) & 1;", d));
        println(fmt::format("\t  {}", dstWrite(fmt::format("{} | (1u << _bit)", d)) + "; }"));
        break;
    }

    case ZYDIS_MNEMONIC_BTR:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _bit = {} & {};", s, opSize - 1));
        println(fmt::format("\t  ctx.flags.cf = ({} >> _bit) & 1;", d));
        println(fmt::format("\t  {}", dstWrite(fmt::format("{} & ~(1u << _bit)", d)) + "; }"));
        break;
    }

    // ---- Control flow ----
    case ZYDIS_MNEMONIC_JMP:
    {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            uint32_t target = static_cast<uint32_t>(address + insn.length + operands[0].imm.value.s);
            bool isLocal = IsLocalAddress(target);
            if (isLocal)
            {
                println(fmt::format("\tgoto loc_{:X};", target));
            }
            else
            {
                // Tail call - direct call for compile-time validation
                println(fmt::format("\tsub_{:X}(ctx, base);", target));
                println("\treturn;");
            }
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 switchTable != config.switchTables.end())
        {
            auto& st = switchTable->second;
            // Use the index register from the JMP's memory operand (e.g. jmp [edx*4+table])
            ZydisRegister switchReg = operands[0].mem.index;
            println(fmt::format("\tswitch ({}) {{", CtxReg(switchReg)));
            for (size_t i = 0; i < st.labels.size(); i++)
            {
                uint32_t lbl = static_cast<uint32_t>(st.labels[i]);
                bool isLocal = IsLocalAddress(lbl);
                if (isLocal)
                    println(fmt::format("\tcase {}: goto loc_{:X};", i, lbl));
                else
                    println(fmt::format("\tcase {}: sub_{:X}(ctx, base); return;", i, lbl));
            }
            println("\tdefault: __builtin_unreachable();");
            println("\t}");
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            std::string ea = FormatMemOperand(insn, operands[0], address);
            println(fmt::format("\tX86_JMP_INDIRECT(ctx, base, X86_MEM_READ_u32(base, {}));", ea));
            println("\treturn;");
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println(fmt::format("\tX86_JMP_INDIRECT(ctx, base, {});", CtxReg(operands[0].reg.value)));
            println("\treturn;");
        }
        break;
    }

    case ZYDIS_MNEMONIC_JO:  case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JB:  case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JZ:  case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JS:  case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JP:  case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JL:  case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_JNLE:
    {
        uint32_t target = static_cast<uint32_t>(address + insn.length + operands[0].imm.value.s);
        bool isLocal = IsLocalAddress(target);
        if (isLocal)
        {
            println(fmt::format("\tif ({}) goto loc_{:X};", FlagsCondition(insn.mnemonic), target));
        }
        else
        {
            println(fmt::format("\tif ({}) {{ sub_{:X}(ctx, base); return; }}", FlagsCondition(insn.mnemonic), target));
        }
        break;
    }

    case ZYDIS_MNEMONIC_JECXZ:
    {
        uint32_t target = static_cast<uint32_t>(address + insn.length + operands[0].imm.value.s);
        bool isLocal = IsLocalAddress(target);
        if (isLocal)
            println(fmt::format("\tif (ctx.ecx == 0) goto loc_{:X};", target));
        else
            println(fmt::format("\tif (ctx.ecx == 0) {{ sub_{:X}(ctx, base); return; }}", target));
        break;
    }

    case ZYDIS_MNEMONIC_LOOP:
    {
        uint32_t target = static_cast<uint32_t>(address + insn.length + operands[0].imm.value.s);
        println("\tctx.ecx--;");
        println(fmt::format("\tif (ctx.ecx != 0) goto loc_{:X};", target));
        break;
    }

    case ZYDIS_MNEMONIC_CALL:
    {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            uint32_t target = static_cast<uint32_t>(address + insn.length + operands[0].imm.value.s);
            println("\tctx.esp -= 4; X86_MEM_WRITE_u32(base, ctx.esp, 0);");
            println(fmt::format("\tsub_{:X}(ctx, base);", target));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            std::string ea = FormatMemOperand(insn, operands[0], address);
            println(fmt::format("\t{{ uint32_t _tgt = X86_MEM_READ_u32(base, {});", ea));
            println("\tctx.esp -= 4; X86_MEM_WRITE_u32(base, ctx.esp, 0);");
            println("\tX86_CALL_INDIRECT(ctx, base, _tgt); }");
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\tctx.esp -= 4; X86_MEM_WRITE_u32(base, ctx.esp, 0);");
            println(fmt::format("\tX86_CALL_INDIRECT(ctx, base, {});", CtxReg(operands[0].reg.value)));
        }
        println("\tctx.esp += 4;");
        break;
    }

    case ZYDIS_MNEMONIC_RET:
    {
        if (insn.operand_count_visible > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            println(fmt::format("\tctx.esp += {};", static_cast<uint16_t>(operands[0].imm.value.u)));
        println("\treturn;");
        break;
    }

    // ---- Conditional moves ----
    case ZYDIS_MNEMONIC_CMOVO:  case ZYDIS_MNEMONIC_CMOVNO:
    case ZYDIS_MNEMONIC_CMOVB:  case ZYDIS_MNEMONIC_CMOVNB:
    case ZYDIS_MNEMONIC_CMOVZ:  case ZYDIS_MNEMONIC_CMOVNZ:
    case ZYDIS_MNEMONIC_CMOVBE: case ZYDIS_MNEMONIC_CMOVNBE:
    case ZYDIS_MNEMONIC_CMOVS:  case ZYDIS_MNEMONIC_CMOVNS:
    case ZYDIS_MNEMONIC_CMOVP:  case ZYDIS_MNEMONIC_CMOVNP:
    case ZYDIS_MNEMONIC_CMOVL:  case ZYDIS_MNEMONIC_CMOVNL:
    case ZYDIS_MNEMONIC_CMOVLE: case ZYDIS_MNEMONIC_CMOVNLE:
        println(fmt::format("\tif ({}) {} = {};", CMovSetCondition(insn.mnemonic), dst(), src()));
        break;

    // ---- Set byte on condition ----
    case ZYDIS_MNEMONIC_SETO:  case ZYDIS_MNEMONIC_SETNO:
    case ZYDIS_MNEMONIC_SETB:  case ZYDIS_MNEMONIC_SETNB:
    case ZYDIS_MNEMONIC_SETZ:  case ZYDIS_MNEMONIC_SETNZ:
    case ZYDIS_MNEMONIC_SETBE: case ZYDIS_MNEMONIC_SETNBE:
    case ZYDIS_MNEMONIC_SETS:  case ZYDIS_MNEMONIC_SETNS:
    case ZYDIS_MNEMONIC_SETP:  case ZYDIS_MNEMONIC_SETNP:
    case ZYDIS_MNEMONIC_SETL:  case ZYDIS_MNEMONIC_SETNL:
    case ZYDIS_MNEMONIC_SETLE: case ZYDIS_MNEMONIC_SETNLE:
        println(fmt::format("\t{};", dstWrite(fmt::format("({}) ? 1 : 0", CMovSetCondition(insn.mnemonic)))));
        break;

    // ---- String operations ----
    case ZYDIS_MNEMONIC_MOVSB:
    case ZYDIS_MNEMONIC_MOVSW:
    case ZYDIS_MNEMONIC_MOVSD:
    {
        int sz = (insn.mnemonic == ZYDIS_MNEMONIC_MOVSB) ? 1 : (insn.mnemonic == ZYDIS_MNEMONIC_MOVSW) ? 2 : 4;
        bool hasRep = (insn.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
        if (hasRep)
        {
            println("\twhile (ctx.ecx) {");
            println(fmt::format("\t\tX86_MEM_WRITE_{}(base, ctx.edi, X86_MEM_READ_{}(base, ctx.esi));", MemSuffix(sz*8), MemSuffix(sz*8)));
            println(fmt::format("\t\tctx.esi += ctx.flags.df ? -{} : {};", sz, sz));
            println(fmt::format("\t\tctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
            println("\t\tctx.ecx--;");
            println("\t}");
        }
        else
        {
            println(fmt::format("\tX86_MEM_WRITE_{}(base, ctx.edi, X86_MEM_READ_{}(base, ctx.esi));", MemSuffix(sz*8), MemSuffix(sz*8)));
            println(fmt::format("\tctx.esi += ctx.flags.df ? -{} : {};", sz, sz));
            println(fmt::format("\tctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
        }
        break;
    }

    case ZYDIS_MNEMONIC_STOSB:
    case ZYDIS_MNEMONIC_STOSW:
    case ZYDIS_MNEMONIC_STOSD:
    {
        int sz = (insn.mnemonic == ZYDIS_MNEMONIC_STOSB) ? 1 : (insn.mnemonic == ZYDIS_MNEMONIC_STOSW) ? 2 : 4;
        const char* srcReg = (sz == 1) ? "X86_REG8L(ctx.eax)" : (sz == 2) ? "X86_REG16(ctx.eax)" : "ctx.eax";
        bool hasRep = (insn.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
        if (hasRep)
        {
            println("\twhile (ctx.ecx) {");
            println(fmt::format("\t\tX86_MEM_WRITE_{}(base, ctx.edi, {});", MemSuffix(sz*8), srcReg));
            println(fmt::format("\t\tctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
            println("\t\tctx.ecx--;");
            println("\t}");
        }
        else
        {
            println(fmt::format("\tX86_MEM_WRITE_{}(base, ctx.edi, {});", MemSuffix(sz*8), srcReg));
            println(fmt::format("\tctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
        }
        break;
    }

    case ZYDIS_MNEMONIC_SCASB:
    case ZYDIS_MNEMONIC_SCASD:
    {
        int sz = (insn.mnemonic == ZYDIS_MNEMONIC_SCASB) ? 1 : 4;
        bool hasRepNE = (insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) != 0;
        bool hasRepE = (insn.attributes & ZYDIS_ATTRIB_HAS_REPE) != 0;
        const char* valReg = (sz == 1) ? "X86_REG8L(ctx.eax)" : "ctx.eax";

        if (hasRepNE || hasRepE)
        {
            println("\twhile (ctx.ecx) {");
            println(fmt::format("\t\t{} _v = X86_MEM_READ_{}(base, ctx.edi);", UnsignedType(sz*8), MemSuffix(sz*8)));
            println(fmt::format("\t\tctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
            println("\t\tctx.ecx--;");
            println(fmt::format("\t\t{{ uint64_t _res = (uint64_t)({})({}) - (uint64_t)_v;", UnsignedType(sz*8), valReg));
            println(fmt::format("\t\t  X86_UPDATE_FLAGS_SUB(ctx, _res, ({})({}) , ({})_v, {}); }}", SignedType(sz*8), valReg, SignedType(sz*8), sz*8));
            if (hasRepNE)
                println("\t\tif (ctx.flags.zf) break;");
            else
                println("\t\tif (!ctx.flags.zf) break;");
            println("\t}");
        }
        else
        {
            println(fmt::format("\t{{ {} _v = X86_MEM_READ_{}(base, ctx.edi);", UnsignedType(sz*8), MemSuffix(sz*8)));
            println(fmt::format("\t  ctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
            println(fmt::format("\t  uint64_t _res = (uint64_t)({})({}) - (uint64_t)_v;", UnsignedType(sz*8), valReg));
            println(fmt::format("\t  X86_UPDATE_FLAGS_SUB(ctx, _res, ({})({}) , ({})_v, {}); }}", SignedType(sz*8), valReg, SignedType(sz*8), sz*8));
        }
        break;
    }

    case ZYDIS_MNEMONIC_CMPSB:
    case ZYDIS_MNEMONIC_CMPSW:
    case ZYDIS_MNEMONIC_CMPSD:
    {
        // CMPSD is shared with SSE cmpsd xmm,xmm/m64,imm8 — disambiguate
        bool isStringCmps = (insn.mnemonic != ZYDIS_MNEMONIC_CMPSD) ||
            insn.operand_count_visible == 0 ||
            (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[0].mem.base == ZYDIS_REGISTER_ESI);
        if (isStringCmps)
        {
            int sz = (insn.mnemonic == ZYDIS_MNEMONIC_CMPSB) ? 1 : (insn.mnemonic == ZYDIS_MNEMONIC_CMPSW) ? 2 : 4;
            bool hasRepNE = (insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) != 0;
            bool hasRepE = (insn.attributes & ZYDIS_ATTRIB_HAS_REPE) != 0;

            if (hasRepNE || hasRepE)
            {
                println("\twhile (ctx.ecx) {");
                println(fmt::format("\t\t{} _a = X86_MEM_READ_{}(base, ctx.esi);", UnsignedType(sz*8), MemSuffix(sz*8)));
                println(fmt::format("\t\t{} _b = X86_MEM_READ_{}(base, ctx.edi);", UnsignedType(sz*8), MemSuffix(sz*8)));
                println(fmt::format("\t\tctx.esi += ctx.flags.df ? -{} : {};", sz, sz));
                println(fmt::format("\t\tctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
                println("\t\tctx.ecx--;");
                println("\t\t{ uint64_t _res = (uint64_t)_a - (uint64_t)_b;");
                println(fmt::format("\t\t  X86_UPDATE_FLAGS_SUB(ctx, _res, ({})_a, ({})_b, {}); }}", SignedType(sz*8), SignedType(sz*8), sz*8));
                if (hasRepNE)
                    println("\t\tif (ctx.flags.zf) break;");
                else
                    println("\t\tif (!ctx.flags.zf) break;");
                println("\t}");
            }
            else
            {
                println(fmt::format("\t{{ {} _a = X86_MEM_READ_{}(base, ctx.esi);", UnsignedType(sz*8), MemSuffix(sz*8)));
                println(fmt::format("\t  {} _b = X86_MEM_READ_{}(base, ctx.edi);", UnsignedType(sz*8), MemSuffix(sz*8)));
                println(fmt::format("\t  ctx.esi += ctx.flags.df ? -{} : {};", sz, sz));
                println(fmt::format("\t  ctx.edi += ctx.flags.df ? -{} : {};", sz, sz));
                println("\t  uint64_t _res = (uint64_t)_a - (uint64_t)_b;");
                println(fmt::format("\t  X86_UPDATE_FLAGS_SUB(ctx, _res, ({})_a, ({})_b, {}); }}", SignedType(sz*8), SignedType(sz*8), sz*8));
            }
        }
        break;
    }

    // ---- Flags ----
    case ZYDIS_MNEMONIC_CLC: println("\tctx.flags.cf = 0;"); break;
    case ZYDIS_MNEMONIC_STC: println("\tctx.flags.cf = 1;"); break;
    case ZYDIS_MNEMONIC_CMC: println("\tctx.flags.cf ^= 1;"); break;
    case ZYDIS_MNEMONIC_CLD: println("\tctx.flags.df = 0;"); break;
    case ZYDIS_MNEMONIC_STD: println("\tctx.flags.df = 1;"); break;

    case ZYDIS_MNEMONIC_LAHF:
        println("\tX86_REG8H(ctx.eax) = X86_PACK_FLAGS_AH(ctx);");
        break;
    case ZYDIS_MNEMONIC_SAHF:
        println("\tX86_UNPACK_FLAGS_AH(ctx, X86_REG8H(ctx.eax));");
        break;

    // ---- FPU ----
    case ZYDIS_MNEMONIC_FLD:
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println(fmt::format("\tX86_FPU_PUSH(ctx, ctx.fp_stack[{}]);",
                operands[0].reg.value - ZYDIS_REGISTER_ST0));
        else
            println(fmt::format("\tX86_FPU_PUSH(ctx, (double)X86_MEM_READ_F{}(base, {}));",
                operands[0].size, FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FILD:
        println(fmt::format("\tX86_FPU_PUSH(ctx, (double)({})(X86_MEM_READ_{}(base, {})));",
            SignedType(operands[0].size), MemSuffix(operands[0].size), FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FST:
    case ZYDIS_MNEMONIC_FSTP:
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println(fmt::format("\tctx.fp_stack[{}] = ctx.fp_stack[ctx.fp_top];",
                operands[0].reg.value - ZYDIS_REGISTER_ST0));
        else
            println(fmt::format("\tX86_MEM_WRITE_F{}(base, {}, ctx.fp_stack[ctx.fp_top]);",
                operands[0].size, FormatMemOperand(insn, operands[0], address)));
        if (insn.mnemonic == ZYDIS_MNEMONIC_FSTP)
            println("\tX86_FPU_POP(ctx);");
        break;

    case ZYDIS_MNEMONIC_FIST:
    case ZYDIS_MNEMONIC_FISTP:
        println(fmt::format("\tX86_MEM_WRITE_{}(base, {}, ({})ctx.fp_stack[ctx.fp_top]);",
            MemSuffix(operands[0].size), FormatMemOperand(insn, operands[0], address),
            SignedType(operands[0].size)));
        if (insn.mnemonic == ZYDIS_MNEMONIC_FISTP)
            println("\tX86_FPU_POP(ctx);");
        break;

    case ZYDIS_MNEMONIC_FADD:
    case ZYDIS_MNEMONIC_FADDP:
        if (insn.operand_count_visible == 2 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_ST0;
            int s = operands[1].reg.value - ZYDIS_REGISTER_ST0;
            println(fmt::format("\tctx.fp_stack[{}] = X86_FPU_ROUND(ctx, ctx.fp_stack[{}] + ctx.fp_stack[{}]);", d, d, s));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            println(fmt::format("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, ctx.fp_stack[ctx.fp_top] + (double)X86_MEM_READ_F{}(base, {}));",
                operands[0].size, FormatMemOperand(insn, operands[0], address)));
        if (insn.mnemonic == ZYDIS_MNEMONIC_FADDP) println("\tX86_FPU_POP(ctx);");
        break;

    case ZYDIS_MNEMONIC_FSUB:
    case ZYDIS_MNEMONIC_FSUBP:
    case ZYDIS_MNEMONIC_FSUBR:
    case ZYDIS_MNEMONIC_FSUBRP:
    {
        bool reversed = (insn.mnemonic == ZYDIS_MNEMONIC_FSUBR || insn.mnemonic == ZYDIS_MNEMONIC_FSUBRP);
        if (insn.operand_count_visible == 2 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_ST0;
            int s = operands[1].reg.value - ZYDIS_REGISTER_ST0;
            if (reversed)
                println(fmt::format("\tctx.fp_stack[{}] = X86_FPU_ROUND(ctx, ctx.fp_stack[{}] - ctx.fp_stack[{}]);", d, s, d));
            else
                println(fmt::format("\tctx.fp_stack[{}] = X86_FPU_ROUND(ctx, ctx.fp_stack[{}] - ctx.fp_stack[{}]);", d, d, s));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            std::string memVal = fmt::format("(double)X86_MEM_READ_F{}(base, {})",
                operands[0].size, FormatMemOperand(insn, operands[0], address));
            if (reversed)
                println(fmt::format("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, {} - ctx.fp_stack[ctx.fp_top]);", memVal));
            else
                println(fmt::format("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, ctx.fp_stack[ctx.fp_top] - {});", memVal));
        }
        if (insn.mnemonic == ZYDIS_MNEMONIC_FSUBP || insn.mnemonic == ZYDIS_MNEMONIC_FSUBRP)
            println("\tX86_FPU_POP(ctx);");
        break;
    }

    case ZYDIS_MNEMONIC_FMUL:
    case ZYDIS_MNEMONIC_FMULP:
        if (insn.operand_count_visible == 2 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_ST0;
            int s = operands[1].reg.value - ZYDIS_REGISTER_ST0;
            println(fmt::format("\tctx.fp_stack[{}] = X86_FPU_ROUND(ctx, ctx.fp_stack[{}] * ctx.fp_stack[{}]);", d, d, s));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            println(fmt::format("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, ctx.fp_stack[ctx.fp_top] * (double)X86_MEM_READ_F{}(base, {}));",
                operands[0].size, FormatMemOperand(insn, operands[0], address)));
        if (insn.mnemonic == ZYDIS_MNEMONIC_FMULP) println("\tX86_FPU_POP(ctx);");
        break;

    case ZYDIS_MNEMONIC_FDIV:
    case ZYDIS_MNEMONIC_FDIVP:
    case ZYDIS_MNEMONIC_FDIVR:
    case ZYDIS_MNEMONIC_FDIVRP:
    {
        bool reversed = (insn.mnemonic == ZYDIS_MNEMONIC_FDIVR || insn.mnemonic == ZYDIS_MNEMONIC_FDIVRP);
        if (insn.operand_count_visible == 2 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_ST0;
            int s = operands[1].reg.value - ZYDIS_REGISTER_ST0;
            if (reversed)
                println(fmt::format("\tctx.fp_stack[{}] = X86_FPU_ROUND(ctx, ctx.fp_stack[{}] / ctx.fp_stack[{}]);", d, s, d));
            else
                println(fmt::format("\tctx.fp_stack[{}] = X86_FPU_ROUND(ctx, ctx.fp_stack[{}] / ctx.fp_stack[{}]);", d, d, s));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            std::string memVal = fmt::format("(double)X86_MEM_READ_F{}(base, {})",
                operands[0].size, FormatMemOperand(insn, operands[0], address));
            if (reversed)
                println(fmt::format("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, {} / ctx.fp_stack[ctx.fp_top]);", memVal));
            else
                println(fmt::format("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, ctx.fp_stack[ctx.fp_top] / {});", memVal));
        }
        if (insn.mnemonic == ZYDIS_MNEMONIC_FDIVP || insn.mnemonic == ZYDIS_MNEMONIC_FDIVRP)
            println("\tX86_FPU_POP(ctx);");
        break;
    }

    case ZYDIS_MNEMONIC_FCHS:
        println("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, -ctx.fp_stack[ctx.fp_top]);");
        break;
    case ZYDIS_MNEMONIC_FABS:
        println("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, fabs(ctx.fp_stack[ctx.fp_top]));");
        break;
    case ZYDIS_MNEMONIC_FSQRT:
        println("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, sqrt(ctx.fp_stack[ctx.fp_top]));");
        break;
    case ZYDIS_MNEMONIC_FSIN:
        println("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, sin(ctx.fp_stack[ctx.fp_top]));");
        break;
    case ZYDIS_MNEMONIC_FCOS:
        println("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, cos(ctx.fp_stack[ctx.fp_top]));");
        break;

    case ZYDIS_MNEMONIC_FPATAN:
        println("\t{ double _x = ctx.fp_stack[ctx.fp_top]; X86_FPU_POP(ctx);");
        println("\t  ctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, atan2(ctx.fp_stack[ctx.fp_top], _x)); }");
        break;

    case ZYDIS_MNEMONIC_FPTAN:
        println("\tctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, tan(ctx.fp_stack[ctx.fp_top]));");
        println("\tX86_FPU_PUSH(ctx, 1.0);");
        break;

    case ZYDIS_MNEMONIC_FXCH:
    {
        int idx = (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            ? (operands[0].reg.value - ZYDIS_REGISTER_ST0) : 1;
        println(fmt::format("\t{{ double _tmp = ctx.fp_stack[ctx.fp_top]; ctx.fp_stack[ctx.fp_top] = ctx.fp_stack[{}]; ctx.fp_stack[{}] = _tmp; }}", idx, idx));
        break;
    }

    case ZYDIS_MNEMONIC_FLDZ:  println("\tX86_FPU_PUSH(ctx, 0.0);"); break;
    case ZYDIS_MNEMONIC_FLD1:  println("\tX86_FPU_PUSH(ctx, 1.0);"); break;
    case ZYDIS_MNEMONIC_FLDPI: println("\tX86_FPU_PUSH(ctx, 3.14159265358979323846);"); break;

    case ZYDIS_MNEMONIC_FCOM:
    case ZYDIS_MNEMONIC_FCOMP:
    case ZYDIS_MNEMONIC_FCOMPP:
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println(fmt::format("\tX86_FPU_COMPARE(ctx, ctx.fp_stack[ctx.fp_top], ctx.fp_stack[{}]);",
                operands[0].reg.value - ZYDIS_REGISTER_ST0));
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            println(fmt::format("\tX86_FPU_COMPARE(ctx, ctx.fp_stack[ctx.fp_top], (double)X86_MEM_READ_F{}(base, {}));",
                operands[0].size, FormatMemOperand(insn, operands[0], address)));
        else
            println("\tX86_FPU_COMPARE(ctx, ctx.fp_stack[ctx.fp_top], ctx.fp_stack[1]);");
        if (insn.mnemonic == ZYDIS_MNEMONIC_FCOMP)
            println("\tX86_FPU_POP(ctx);");
        else if (insn.mnemonic == ZYDIS_MNEMONIC_FCOMPP)
        { println("\tX86_FPU_POP(ctx);"); println("\tX86_FPU_POP(ctx);"); }
        break;

    case ZYDIS_MNEMONIC_FUCOM:
    case ZYDIS_MNEMONIC_FUCOMP:
    case ZYDIS_MNEMONIC_FUCOMPP:
    {
        int idx = (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            ? (operands[0].reg.value - ZYDIS_REGISTER_ST0) : 1;
        println(fmt::format("\tX86_FPU_COMPARE(ctx, ctx.fp_stack[ctx.fp_top], ctx.fp_stack[{}]);", idx));
        if (insn.mnemonic == ZYDIS_MNEMONIC_FUCOMP)
            println("\tX86_FPU_POP(ctx);");
        else if (insn.mnemonic == ZYDIS_MNEMONIC_FUCOMPP)
        { println("\tX86_FPU_POP(ctx);"); println("\tX86_FPU_POP(ctx);"); }
        break;
    }

    case ZYDIS_MNEMONIC_FCOMI:
    case ZYDIS_MNEMONIC_FCOMIP:
    case ZYDIS_MNEMONIC_FUCOMI:
    case ZYDIS_MNEMONIC_FUCOMIP:
    {
        int idx = operands[1].reg.value - ZYDIS_REGISTER_ST0;
        println(fmt::format("\tX86_FPU_COMPARE_EFLAGS(ctx, ctx.fp_stack[ctx.fp_top], ctx.fp_stack[{}]);", idx));
        if (insn.mnemonic == ZYDIS_MNEMONIC_FCOMIP || insn.mnemonic == ZYDIS_MNEMONIC_FUCOMIP)
            println("\tX86_FPU_POP(ctx);");
        break;
    }

    case ZYDIS_MNEMONIC_FNSTSW:
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println("\tX86_REG16(ctx.eax) = X86_FPU_STATUS(ctx);");
        else
            println(fmt::format("\tX86_MEM_WRITE_u16(base, {}, X86_FPU_STATUS(ctx));",
                FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FNSTCW:
        println(fmt::format("\tX86_MEM_WRITE_u16(base, {}, ctx.fp_control);",
            FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FLDCW:
        println(fmt::format("\tctx.fp_control = X86_MEM_READ_u16(base, {});",
            FormatMemOperand(insn, operands[0], address)));
        break;

    // ---- SSE ----
    case ZYDIS_MNEMONIC_MOVSS:
    case ZYDIS_MNEMONIC_MOVAPS:
    case ZYDIS_MNEMONIC_MOVUPS:
    case ZYDIS_MNEMONIC_MOVD:
    {
        auto IsMMReg  = [](ZydisRegister r){ return r >= ZYDIS_REGISTER_MM0  && r <= ZYDIS_REGISTER_MM7;  };
        auto IsXmmReg = [](ZydisRegister r){ return r >= ZYDIS_REGISTER_XMM0 && r <= ZYDIS_REGISTER_XMM7; };

        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (insn.mnemonic == ZYDIS_MNEMONIC_MOVSS)
            {
                println(fmt::format("\tctx.xmm[{}].f32[0] = ctx.xmm[{}].f32[0];",
                    operands[0].reg.value - ZYDIS_REGISTER_XMM0, operands[1].reg.value - ZYDIS_REGISTER_XMM0));
            }
            else if (insn.mnemonic == ZYDIS_MNEMONIC_MOVD)
            {
                ZydisRegister dst_reg = operands[0].reg.value;
                ZydisRegister src_reg = operands[1].reg.value;
                if (IsMMReg(dst_reg))
                {
                    // movd mm, r32
                    int d = dst_reg - ZYDIS_REGISTER_MM0;
                    println(fmt::format("\tctx.mm[{}].u64 = (uint64_t)(uint32_t){};", d, CtxReg(src_reg)));
                }
                else if (IsMMReg(src_reg))
                {
                    // movd r32/xmm, mm
                    int s = src_reg - ZYDIS_REGISTER_MM0;
                    if (IsXmmReg(dst_reg))
                    {
                        int d = dst_reg - ZYDIS_REGISTER_XMM0;
                        println(fmt::format("\tctx.xmm[{}].u32[0] = ctx.mm[{}].u32[0]; ctx.xmm[{}].u32[1] = ctx.xmm[{}].u32[2] = ctx.xmm[{}].u32[3] = 0;",
                            d, s, d, d, d));
                    }
                    else
                    {
                        println(fmt::format("\t{} = ctx.mm[{}].u32[0];", CtxReg(dst_reg), s));
                    }
                }
                else if (IsXmmReg(dst_reg))
                {
                    // movd xmm, r32
                    int d = dst_reg - ZYDIS_REGISTER_XMM0;
                    println(fmt::format("\tctx.xmm[{}].u32[0] = (uint32_t){}; ctx.xmm[{}].u32[1] = ctx.xmm[{}].u32[2] = ctx.xmm[{}].u32[3] = 0;",
                        d, CtxReg(src_reg), d, d, d));
                }
                else
                {
                    // movd r32, xmm
                    println(fmt::format("\t{} = ctx.xmm[{}].u32[0];",
                        CtxReg(dst_reg), src_reg - ZYDIS_REGISTER_XMM0));
                }
            }
            else
            {
                println(fmt::format("\tctx.xmm[{}] = ctx.xmm[{}];",
                    operands[0].reg.value - ZYDIS_REGISTER_XMM0, operands[1].reg.value - ZYDIS_REGISTER_XMM0));
            }
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            std::string ea = FormatMemOperand(insn, operands[1], address);
            if (insn.mnemonic == ZYDIS_MNEMONIC_MOVD && IsMMReg(operands[0].reg.value))
            {
                // movd mm, mem
                int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
                println(fmt::format("\tctx.mm[{}].u64 = (uint64_t)X86_MEM_READ_u32(base, {});", d, ea));
            }
            else
            {
                int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                if (insn.mnemonic == ZYDIS_MNEMONIC_MOVSS || insn.mnemonic == ZYDIS_MNEMONIC_MOVD)
                    println(fmt::format("\tctx.xmm[{}].u32[0] = X86_MEM_READ_u32(base, {});", d, ea));
                else
                    println(fmt::format("\tX86_MEM_READ_XMM(base, {}, ctx.xmm[{}]);", ea, d));
            }
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            std::string ea = FormatMemOperand(insn, operands[0], address);
            if (insn.mnemonic == ZYDIS_MNEMONIC_MOVD && IsMMReg(operands[1].reg.value))
            {
                // movd mem, mm
                int s = operands[1].reg.value - ZYDIS_REGISTER_MM0;
                println(fmt::format("\tX86_MEM_WRITE_u32(base, {}, ctx.mm[{}].u32[0]);", ea, s));
            }
            else
            {
                int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
                if (insn.mnemonic == ZYDIS_MNEMONIC_MOVSS || insn.mnemonic == ZYDIS_MNEMONIC_MOVD)
                    println(fmt::format("\tX86_MEM_WRITE_u32(base, {}, ctx.xmm[{}].u32[0]);", ea, s));
                else
                    println(fmt::format("\tX86_MEM_WRITE_XMM(base, {}, ctx.xmm[{}]);", ea, s));
            }
        }
        break;
    }

    case ZYDIS_MNEMONIC_ADDSS: case ZYDIS_MNEMONIC_SUBSS:
    case ZYDIS_MNEMONIC_MULSS: case ZYDIS_MNEMONIC_DIVSS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* op;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_ADDSS: op = "+="; break;
        case ZYDIS_MNEMONIC_SUBSS: op = "-="; break;
        case ZYDIS_MNEMONIC_MULSS: op = "*="; break;
        case ZYDIS_MNEMONIC_DIVSS: op = "/="; break;
        default: op = "?="; break;
        }
        println(fmt::format("\tctx.xmm[{}].f32[0] {} {};", d, op, srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_MINSS: case ZYDIS_MNEMONIC_MAXSS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* fn = (insn.mnemonic == ZYDIS_MNEMONIC_MINSS) ? "fminf" : "fmaxf";
        println(fmt::format("\tctx.xmm[{}].f32[0] = {}(ctx.xmm[{}].f32[0], {});", d, fn, d, srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_SQRTSS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\tctx.xmm[{}].f32[0] = sqrtf({});", d, srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_RSQRTSS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\tctx.xmm[{}].f32[0] = 1.0f / sqrtf({});", d, srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_CMPSS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        uint8_t imm = static_cast<uint8_t>(operands[2].imm.value.u);
        const char* cmpExpr;
        switch (imm & 7) {
        case 0: cmpExpr = "=="; break; // EQ
        case 1: cmpExpr = "<";  break; // LT
        case 2: cmpExpr = "<="; break; // LE
        case 3: cmpExpr = "!="; break; // UNORD (approx as !=)
        case 4: cmpExpr = "!="; break; // NEQ
        case 5: cmpExpr = ">="; break; // NLT
        case 6: cmpExpr = ">";  break; // NLE
        default: cmpExpr = "=="; break; // ORD (approx as ==)
        }
        println(fmt::format("\tctx.xmm[{}].u32[0] = (ctx.xmm[{}].f32[0] {} {}) ? 0xFFFFFFFFu : 0u;",
            d, d, cmpExpr, srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_CVTSS2SI:
    {
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\t{} = (uint32_t)(int32_t)lrintf({});", dst(), srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_ADDPS: case ZYDIS_MNEMONIC_SUBPS:
    case ZYDIS_MNEMONIC_MULPS: case ZYDIS_MNEMONIC_DIVPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.xmm[{}]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_XMM_VAL(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macroName;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_ADDPS: macroName = "X86_SSE_ADDPS"; break;
        case ZYDIS_MNEMONIC_SUBPS: macroName = "X86_SSE_SUBPS"; break;
        case ZYDIS_MNEMONIC_MULPS: macroName = "X86_SSE_MULPS"; break;
        case ZYDIS_MNEMONIC_DIVPS: macroName = "X86_SSE_DIVPS"; break;
        default: macroName = "X86_SSE_UNKNOWNPS"; break;
        }
        println(fmt::format("\t{}(ctx.xmm[{}], {});", macroName, d, srcExpr));
        break;
    }

    case ZYDIS_MNEMONIC_XORPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
            if (d == s)
                println(fmt::format("\tmemset(&ctx.xmm[{}], 0, sizeof(ctx.xmm[{}]));", d, d));
            else
                println(fmt::format("\tX86_SSE_XORPS(ctx.xmm[{}], ctx.xmm[{}]);", d, s));
        }
        else
            println(fmt::format("\tX86_SSE_XORPS(ctx.xmm[{}], X86_MEM_READ_XMM_VAL(base, {}));",
                d, FormatMemOperand(insn, operands[1], address)));
        break;
    }

    case ZYDIS_MNEMONIC_ANDPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println(fmt::format("\tX86_SSE_ANDPS(ctx.xmm[{}], ctx.xmm[{}]);", d, operands[1].reg.value - ZYDIS_REGISTER_XMM0));
        else
            println(fmt::format("\tX86_SSE_ANDPS(ctx.xmm[{}], X86_MEM_READ_XMM_VAL(base, {}));",
                d, FormatMemOperand(insn, operands[1], address)));
        break;
    }

    case ZYDIS_MNEMONIC_ORPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println(fmt::format("\tX86_SSE_ORPS(ctx.xmm[{}], ctx.xmm[{}]);", d, operands[1].reg.value - ZYDIS_REGISTER_XMM0));
        else
            println(fmt::format("\tX86_SSE_ORPS(ctx.xmm[{}], X86_MEM_READ_XMM_VAL(base, {}));",
                d, FormatMemOperand(insn, operands[1], address)));
        break;
    }

    case ZYDIS_MNEMONIC_COMISS:
    case ZYDIS_MNEMONIC_UCOMISS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\tX86_SSE_COMPARE_EFLAGS(ctx, ctx.xmm[{}].f32[0], {});", d, srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_CVTSI2SS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        println(fmt::format("\tctx.xmm[{}].f32[0] = (float)(int32_t){};", d, src()));
        break;
    }

    case ZYDIS_MNEMONIC_CVTTSS2SI:
    {
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\t{} = (uint32_t)(int32_t){};", dst(), srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_CVTSS2SD:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f32[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F32(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\tctx.xmm[{}].f64[0] = (double){};", d, srcVal));
        break;
    }

    case ZYDIS_MNEMONIC_CVTSD2SS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = fmt::format("ctx.xmm[{}].f64[0]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcVal = fmt::format("X86_MEM_READ_F64(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\tctx.xmm[{}].f32[0] = (float){};", d, srcVal));
        break;
    }

    // ---- Misc / NOP ----
    case ZYDIS_MNEMONIC_NOP:
    case ZYDIS_MNEMONIC_INT3:
    case ZYDIS_MNEMONIC_PAUSE:
        break;

    case ZYDIS_MNEMONIC_LEAVE:
        println("\tctx.esp = ctx.ebp;");
        println("\tctx.ebp = X86_MEM_READ_u32(base, ctx.esp);");
        println("\tctx.esp += 4;");
        break;

    // ---- BSWAP ----
    case ZYDIS_MNEMONIC_BSWAP:
        println(fmt::format("\t{0} = (({0} >> 24) & 0xFF) | (({0} >> 8) & 0xFF00) | (({0} << 8) & 0xFF0000) | (({0} << 24) & 0xFF000000u);", dst()));
        break;

    // ---- CMPXCHG ----
    case ZYDIS_MNEMONIC_CMPXCHG:
    {
        std::string d = dst(), s = src();
        std::string accum = (opSize == 8) ? "X86_REG8L(ctx.eax)" :
                            (opSize == 16) ? "X86_REG16(ctx.eax)" : "ctx.eax";
        println(fmt::format("\t{{ {} _d = {};", utype(), d));
        println(fmt::format("\t  if (({})({}) == _d) {{", utype(), accum));
        println(fmt::format("\t    ctx.flags.zf = 1;"));
        println(fmt::format("\t    {};", dstWrite(s)));
        println(fmt::format("\t  }} else {{"));
        println(fmt::format("\t    ctx.flags.zf = 0;"));
        println(fmt::format("\t    {} = _d;", accum));
        println(fmt::format("\t  }} }}"));
        break;
    }

    // ---- XADD ----
    case ZYDIS_MNEMONIC_XADD:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ {} _d = {}; {} _s = {};", utype(), d, utype(), s));
        println(fmt::format("\t  uint64_t _res = (uint64_t)_d + (uint64_t)_s;"));
        println(fmt::format("\t  X86_UPDATE_FLAGS_ADD(ctx, _res, ({}){}, ({}){}, {});", stype(), "_d", stype(), "_s", opSize));
        println(fmt::format("\t  {} = _d;", s));
        println(fmt::format("\t  {}; }}", dstWrite(fmt::format("({}){}", utype(), "_res"))));
        break;
    }

    // ---- RCR ----
    case ZYDIS_MNEMONIC_RCR:
    {
        std::string d = dst(), s = src();
        println(fmt::format("\t{{ auto _cnt = {} & 0x1F;", s));
        println(fmt::format("\t  if (_cnt) {{"));
        println(fmt::format("\t    uint64_t _v = (uint64_t)({})({}) | ((uint64_t)ctx.flags.cf << {});", utype(), d, opSize));
        println(fmt::format("\t    _cnt %= {};", opSize + 1));
        println(fmt::format("\t    uint64_t _rot = (_v >> _cnt) | (_v << ({} + 1 - _cnt));", opSize));
        println(fmt::format("\t    ctx.flags.cf = (_rot >> {}) & 1;", opSize));
        println(fmt::format("\t    {}", dstWrite(fmt::format("({}){}", utype(), "_rot")) + ";"));
        println(fmt::format("\t  }} }}"));
        break;
    }

    // ---- PUSHFD / POPFD ----
    case ZYDIS_MNEMONIC_PUSHFD:
        println("\t{ uint32_t _fl = X86_PACK_EFLAGS(ctx);");
        println("\t  ctx.esp -= 4;");
        println("\t  X86_MEM_WRITE_u32(base, ctx.esp, _fl); }");
        break;

    case ZYDIS_MNEMONIC_POPFD:
        println("\t{ uint32_t _fl = X86_MEM_READ_u32(base, ctx.esp);");
        println("\t  ctx.esp += 4;");
        println("\t  X86_UNPACK_EFLAGS(ctx, _fl); }");
        break;

    // ---- CPUID ----
    case ZYDIS_MNEMONIC_CPUID:
        println("\tX86_CPUID(ctx);");
        break;

    // ---- RDTSC ----
    case ZYDIS_MNEMONIC_RDTSC:
        println("\t{ uint64_t _tsc = X86_RDTSC();");
        println("\t  ctx.eax = (uint32_t)_tsc; ctx.edx = (uint32_t)(_tsc >> 32); }");
        break;

    // ---- CLI / STI ----
    case ZYDIS_MNEMONIC_CLI:
    case ZYDIS_MNEMONIC_STI:
        println("\t// cli/sti - ignored in recompilation");
        break;

    // ---- IN / OUT ----
    case ZYDIS_MNEMONIC_IN:
        println(fmt::format("\t{} = 0; // in from port - stubbed", dst()));
        break;
    case ZYDIS_MNEMONIC_OUT:
        println("\t// out to port - stubbed");
        break;

    // ---- INSB ----
    case ZYDIS_MNEMONIC_INSB:
        println("\t// insb - stubbed (I/O port string input)");
        break;

    // ---- SGDT / WBINVD ----
    case ZYDIS_MNEMONIC_SGDT:
        println("\t// sgdt - stubbed (store GDT register)");
        break;
    case ZYDIS_MNEMONIC_WBINVD:
        println("\t// wbinvd - stubbed (write back and invalidate cache)");
        break;

    // ---- INT ----
    case ZYDIS_MNEMONIC_INT:
        println(fmt::format("\t// int 0x{:X} - stubbed", static_cast<uint8_t>(operands[0].imm.value.u)));
        break;

    // ---- HLT ----
    case ZYDIS_MNEMONIC_HLT:
        println("\t// hlt - ignored");
        break;

    // ---- ENTER ----
    case ZYDIS_MNEMONIC_ENTER:
    {
        uint16_t allocSize = static_cast<uint16_t>(operands[0].imm.value.u);
        println("\tctx.esp -= 4;");
        println("\tX86_MEM_WRITE_u32(base, ctx.esp, ctx.ebp);");
        println("\tctx.ebp = ctx.esp;");
        if (allocSize > 0)
            println(fmt::format("\tctx.esp -= {};", allocSize));
        break;
    }

    // ---- XLAT ----
    case ZYDIS_MNEMONIC_XLAT:
        println("\tX86_REG8L(ctx.eax) = X86_MEM_READ_u8(base, ctx.ebx + X86_REG8L(ctx.eax));");
        break;

    // ---- PREFETCHNTA ----
    case ZYDIS_MNEMONIC_PREFETCHNTA:
        println("\t// prefetchnta - no-op");
        break;

    // ---- Additional FPU ----
    case ZYDIS_MNEMONIC_FLDL2E:
        println("\tX86_FPU_PUSH(ctx, 1.4426950408889634); // log2(e)");
        break;
    case ZYDIS_MNEMONIC_FLDLN2:
        println("\tX86_FPU_PUSH(ctx, 0.6931471805599453); // ln(2)");
        break;
    case ZYDIS_MNEMONIC_FLDLG2:
        println("\tX86_FPU_PUSH(ctx, 0.3010299957316877); // log10(2)");
        break;

    case ZYDIS_MNEMONIC_FYL2X:
        println("\t{ double _y = ctx.fp_stack[(ctx.fp_top + 1) & 7];");
        println("\t  double _x = ctx.fp_stack[ctx.fp_top];");
        println("\t  X86_FPU_POP(ctx);");
        println("\t  ctx.fp_stack[ctx.fp_top] = _y * log2(_x); }");
        break;

    case ZYDIS_MNEMONIC_F2XM1:
        println("\tctx.fp_stack[ctx.fp_top] = pow(2.0, ctx.fp_stack[ctx.fp_top]) - 1.0;");
        break;

    case ZYDIS_MNEMONIC_FSCALE:
        println("\tctx.fp_stack[ctx.fp_top] = ldexp(ctx.fp_stack[ctx.fp_top], (int)ctx.fp_stack[(ctx.fp_top + 1) & 7]);");
        break;

    case ZYDIS_MNEMONIC_FRNDINT:
        println("\tctx.fp_stack[ctx.fp_top] = nearbyint(ctx.fp_stack[ctx.fp_top]);");
        break;

    case ZYDIS_MNEMONIC_FTST:
        println("\tX86_FPU_COMPARE(ctx, ctx.fp_stack[ctx.fp_top], 0.0);");
        break;

    case ZYDIS_MNEMONIC_FXAM:
        println("\tctx.fp_status &= ~0x4700;");
        println("\t{ double _v = ctx.fp_stack[ctx.fp_top];");
        println("\t  if (_v != _v) ctx.fp_status |= 0x0100;");
        println("\t  else if (_v == 0.0) ctx.fp_status |= 0x4000;");
        println("\t  else ctx.fp_status |= 0x0400; }");
        break;

    case ZYDIS_MNEMONIC_FIADD:
        println(fmt::format("\tctx.fp_stack[ctx.fp_top] += (double)({})(X86_MEM_READ_{}(base, {}));",
            SignedType(operands[0].size), MemSuffix(operands[0].size), FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FIMUL:
        println(fmt::format("\tctx.fp_stack[ctx.fp_top] *= (double)({})(X86_MEM_READ_{}(base, {}));",
            SignedType(operands[0].size), MemSuffix(operands[0].size), FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FIDIV:
        println(fmt::format("\tctx.fp_stack[ctx.fp_top] /= (double)({})(X86_MEM_READ_{}(base, {}));",
            SignedType(operands[0].size), MemSuffix(operands[0].size), FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FISUB:
        println(fmt::format("\tctx.fp_stack[ctx.fp_top] -= (double)({})(X86_MEM_READ_{}(base, {}));",
            SignedType(operands[0].size), MemSuffix(operands[0].size), FormatMemOperand(insn, operands[0], address)));
        break;

    case ZYDIS_MNEMONIC_FWAIT:
        println("\t// fwait - no-op");
        break;

    case ZYDIS_MNEMONIC_FNCLEX:
        println("\tctx.fp_status &= ~0x80BF; // clear exception flags");
        break;

    case ZYDIS_MNEMONIC_FNSAVE:
        println(fmt::format("\t{{ uint32_t _ea = {};", FormatMemOperand(insn, operands[0], address)));
        println("\t  X86_MEM_WRITE_u16(base, _ea, ctx.fp_control);");
        println("\t  X86_MEM_WRITE_u16(base, _ea + 4, ctx.fp_status);");
        println("\t  for (int _i = 0; _i < 8; _i++)");
        println("\t    X86_MEM_WRITE_F64(base, _ea + 28 + _i * 10, ctx.fp_stack[(_i + ctx.fp_top) & 7]);");
        println("\t  ctx.fp_top = 0; ctx.fp_control = 0x037F; ctx.fp_status = 0; }");
        break;

    case ZYDIS_MNEMONIC_FRSTOR:
        println(fmt::format("\t{{ uint32_t _ea = {};", FormatMemOperand(insn, operands[0], address)));
        println("\t  ctx.fp_control = X86_MEM_READ_u16(base, _ea);");
        println("\t  ctx.fp_status = X86_MEM_READ_u16(base, _ea + 4);");
        println("\t  ctx.fp_top = (ctx.fp_status >> 11) & 7;");
        println("\t  for (int _i = 0; _i < 8; _i++)");
        println("\t    ctx.fp_stack[(_i + ctx.fp_top) & 7] = X86_MEM_READ_F64(base, _ea + 28 + _i * 10); }");
        break;

    // ---- Additional SSE ----
    case ZYDIS_MNEMONIC_SHUFPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        uint8_t imm = static_cast<uint8_t>(operands[2].imm.value.u);
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\t{{ X86XmmReg _tmp;"));
            println(fmt::format("\t  _tmp.f32[0] = ctx.xmm[{}].f32[{} & 3];", d, imm));
            println(fmt::format("\t  _tmp.f32[1] = ctx.xmm[{}].f32[({} >> 2) & 3];", d, imm));
            println(fmt::format("\t  _tmp.f32[2] = ctx.xmm[{}].f32[({} >> 4) & 3];", s, imm));
            println(fmt::format("\t  _tmp.f32[3] = ctx.xmm[{}].f32[({} >> 6) & 3];", s, imm));
            println(fmt::format("\t  ctx.xmm[{}] = _tmp; }}", d));
        }
        else
        {
            std::string ea = FormatMemOperand(insn, operands[1], address);
            println(fmt::format("\t{{ X86XmmReg _s; X86_MEM_READ_XMM(base, {}, _s); X86XmmReg _tmp;", ea));
            println(fmt::format("\t  _tmp.f32[0] = ctx.xmm[{}].f32[{} & 3];", d, imm));
            println(fmt::format("\t  _tmp.f32[1] = ctx.xmm[{}].f32[({} >> 2) & 3];", d, imm));
            println(fmt::format("\t  _tmp.f32[2] = _s.f32[({} >> 4) & 3];", imm));
            println(fmt::format("\t  _tmp.f32[3] = _s.f32[({} >> 6) & 3];", imm));
            println(fmt::format("\t  ctx.xmm[{}] = _tmp; }}", d));
        }
        break;
    }

    case ZYDIS_MNEMONIC_UNPCKLPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\t{{ X86XmmReg _tmp;"));
            println(fmt::format("\t  _tmp.f32[0] = ctx.xmm[{}].f32[0]; _tmp.f32[1] = ctx.xmm[{}].f32[0];", d, s));
            println(fmt::format("\t  _tmp.f32[2] = ctx.xmm[{}].f32[1]; _tmp.f32[3] = ctx.xmm[{}].f32[1];", d, s));
            println(fmt::format("\t  ctx.xmm[{}] = _tmp; }}", d));
        }
        else
        {
            std::string ea = FormatMemOperand(insn, operands[1], address);
            println(fmt::format("\t{{ X86XmmReg _s; X86_MEM_READ_XMM(base, {}, _s); X86XmmReg _tmp;", ea));
            println(fmt::format("\t  _tmp.f32[0] = ctx.xmm[{}].f32[0]; _tmp.f32[1] = _s.f32[0];", d));
            println(fmt::format("\t  _tmp.f32[2] = ctx.xmm[{}].f32[1]; _tmp.f32[3] = _s.f32[1];", d));
            println(fmt::format("\t  ctx.xmm[{}] = _tmp; }}", d));
        }
        break;
    }

    case ZYDIS_MNEMONIC_UNPCKHPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\t{{ X86XmmReg _tmp;"));
            println(fmt::format("\t  _tmp.f32[0] = ctx.xmm[{}].f32[2]; _tmp.f32[1] = ctx.xmm[{}].f32[2];", d, s));
            println(fmt::format("\t  _tmp.f32[2] = ctx.xmm[{}].f32[3]; _tmp.f32[3] = ctx.xmm[{}].f32[3];", d, s));
            println(fmt::format("\t  ctx.xmm[{}] = _tmp; }}", d));
        }
        else
        {
            std::string ea = FormatMemOperand(insn, operands[1], address);
            println(fmt::format("\t{{ X86XmmReg _s; X86_MEM_READ_XMM(base, {}, _s); X86XmmReg _tmp;", ea));
            println(fmt::format("\t  _tmp.f32[0] = ctx.xmm[{}].f32[2]; _tmp.f32[1] = _s.f32[2];", d));
            println(fmt::format("\t  _tmp.f32[2] = ctx.xmm[{}].f32[3]; _tmp.f32[3] = _s.f32[3];", d));
            println(fmt::format("\t  ctx.xmm[{}] = _tmp; }}", d));
        }
        break;
    }

    case ZYDIS_MNEMONIC_MOVNTPS:
    {
        int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
        std::string ea = FormatMemOperand(insn, operands[0], address);
        println(fmt::format("\tX86_MEM_WRITE_XMM(base, {}, ctx.xmm[{}]);", ea, s));
        break;
    }

    case ZYDIS_MNEMONIC_MOVLHPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
        println(fmt::format("\tctx.xmm[{}].u64[1] = ctx.xmm[{}].u64[0];", d, s));
        break;
    }

    case ZYDIS_MNEMONIC_MOVHLPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
        println(fmt::format("\tctx.xmm[{}].u64[0] = ctx.xmm[{}].u64[1];", d, s));
        break;
    }

    case ZYDIS_MNEMONIC_MOVLPS:
    {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\tctx.xmm[{}].u64[0] = X86_MEM_READ_u64(base, {});", d, FormatMemOperand(insn, operands[1], address)));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\tX86_MEM_WRITE_u64(base, {}, ctx.xmm[{}].u64[0]);", FormatMemOperand(insn, operands[0], address), s));
        }
        break;
    }

    case ZYDIS_MNEMONIC_SFENCE:
        println("\t// sfence - no-op in recompilation");
        break;

    // ---- MMX ----
    case ZYDIS_MNEMONIC_MOVQ:
    {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
            int s = operands[1].reg.value - ZYDIS_REGISTER_MM0;
            println(fmt::format("\tctx.mm[{}].u64 = ctx.mm[{}].u64;", d, s));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
            println(fmt::format("\tctx.mm[{}].u64 = X86_MEM_READ_u64(base, {});", d, FormatMemOperand(insn, operands[1], address)));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_MM0;
            println(fmt::format("\tX86_MEM_WRITE_u64(base, {}, ctx.mm[{}].u64);", FormatMemOperand(insn, operands[0], address), s));
        }
        break;
    }

    case ZYDIS_MNEMONIC_EMMS:
        println("\t// emms - clear MMX state (no-op)");
        break;

    case ZYDIS_MNEMONIC_PADDW:
    case ZYDIS_MNEMONIC_PADDD:
    case ZYDIS_MNEMONIC_PSUBW:
    case ZYDIS_MNEMONIC_PSUBD:
    case ZYDIS_MNEMONIC_PSUBSW:
    case ZYDIS_MNEMONIC_PMULLW:
    case ZYDIS_MNEMONIC_PMADDWD:
    case ZYDIS_MNEMONIC_PXOR:
    case ZYDIS_MNEMONIC_PAND:
    case ZYDIS_MNEMONIC_POR:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.mm[{}]", operands[1].reg.value - ZYDIS_REGISTER_MM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_MMX(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macro;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_PADDW:   macro = "X86_MMX_PADDW"; break;
        case ZYDIS_MNEMONIC_PADDD:   macro = "X86_MMX_PADDD"; break;
        case ZYDIS_MNEMONIC_PSUBW:   macro = "X86_MMX_PSUBW"; break;
        case ZYDIS_MNEMONIC_PSUBD:   macro = "X86_MMX_PSUBD"; break;
        case ZYDIS_MNEMONIC_PSUBSW:  macro = "X86_MMX_PSUBSW"; break;
        case ZYDIS_MNEMONIC_PMULLW:  macro = "X86_MMX_PMULLW"; break;
        case ZYDIS_MNEMONIC_PMADDWD: macro = "X86_MMX_PMADDWD"; break;
        case ZYDIS_MNEMONIC_PXOR:    macro = "X86_MMX_PXOR"; break;
        case ZYDIS_MNEMONIC_PAND:    macro = "X86_MMX_PAND"; break;
        case ZYDIS_MNEMONIC_POR:     macro = "X86_MMX_POR"; break;
        default: macro = "X86_MMX_UNKNOWN"; break;
        }
        println(fmt::format("\t{}(ctx.mm[{}], {});", macro, d, srcExpr));
        break;
    }

    case ZYDIS_MNEMONIC_PSLLW:
    case ZYDIS_MNEMONIC_PSLLD:
    case ZYDIS_MNEMONIC_PSRLW:
    case ZYDIS_MNEMONIC_PSRLQ:
    case ZYDIS_MNEMONIC_PSRAD:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string cnt;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            cnt = fmt::format("{}", operands[1].imm.value.u);
        else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            cnt = fmt::format("(int)ctx.mm[{}].u64", operands[1].reg.value - ZYDIS_REGISTER_MM0);
        else
            cnt = fmt::format("(int)X86_MEM_READ_u64(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macro;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_PSLLW: macro = "X86_MMX_PSLLW"; break;
        case ZYDIS_MNEMONIC_PSLLD: macro = "X86_MMX_PSLLD"; break;
        case ZYDIS_MNEMONIC_PSRLW: macro = "X86_MMX_PSRLW"; break;
        case ZYDIS_MNEMONIC_PSRLQ: macro = "X86_MMX_PSRLQ"; break;
        case ZYDIS_MNEMONIC_PSRAD: macro = "X86_MMX_PSRAD"; break;
        default: macro = "X86_MMX_UNKNOWN"; break;
        }
        println(fmt::format("\t{}(ctx.mm[{}], {});", macro, d, cnt));
        break;
    }

    case ZYDIS_MNEMONIC_PUNPCKLBW:
    case ZYDIS_MNEMONIC_PUNPCKHBW:
    case ZYDIS_MNEMONIC_PUNPCKLWD:
    case ZYDIS_MNEMONIC_PUNPCKHWD:
    case ZYDIS_MNEMONIC_PUNPCKLDQ:
    case ZYDIS_MNEMONIC_PUNPCKHDQ:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.mm[{}]", operands[1].reg.value - ZYDIS_REGISTER_MM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_MMX(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macro;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_PUNPCKLBW: macro = "X86_MMX_PUNPCKLBW"; break;
        case ZYDIS_MNEMONIC_PUNPCKHBW: macro = "X86_MMX_PUNPCKHBW"; break;
        case ZYDIS_MNEMONIC_PUNPCKLWD: macro = "X86_MMX_PUNPCKLWD"; break;
        case ZYDIS_MNEMONIC_PUNPCKHWD: macro = "X86_MMX_PUNPCKHWD"; break;
        case ZYDIS_MNEMONIC_PUNPCKLDQ: macro = "X86_MMX_PUNPCKLDQ"; break;
        case ZYDIS_MNEMONIC_PUNPCKHDQ: macro = "X86_MMX_PUNPCKHDQ"; break;
        default: macro = "X86_MMX_UNKNOWN"; break;
        }
        println(fmt::format("\t{}(ctx.mm[{}], {});", macro, d, srcExpr));
        break;
    }

    case ZYDIS_MNEMONIC_PACKSSDW:
    case ZYDIS_MNEMONIC_PACKUSWB:
    case ZYDIS_MNEMONIC_PACKSSWB:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.mm[{}]", operands[1].reg.value - ZYDIS_REGISTER_MM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_MMX(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macro;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_PACKSSDW: macro = "X86_MMX_PACKSSDW"; break;
        case ZYDIS_MNEMONIC_PACKUSWB: macro = "X86_MMX_PACKUSWB"; break;
        case ZYDIS_MNEMONIC_PACKSSWB: macro = "X86_MMX_PACKSSWB"; break;
        default: macro = "X86_MMX_UNKNOWN"; break;
        }
        println(fmt::format("\t{}(ctx.mm[{}], {});", macro, d, srcExpr));
        break;
    }

    case ZYDIS_MNEMONIC_PSHUFW:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        uint8_t imm = static_cast<uint8_t>(operands[2].imm.value.u);
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.mm[{}]", operands[1].reg.value - ZYDIS_REGISTER_MM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_MMX(base, {})", FormatMemOperand(insn, operands[1], address));
        println(fmt::format("\tX86_MMX_PSHUFW(ctx.mm[{}], {}, 0x{:02X});", d, srcExpr, imm));
        break;
    }

    // ---- SSE packed: minps, maxps, cmpps, andnps, movmskps ----
    case ZYDIS_MNEMONIC_MINPS: case ZYDIS_MNEMONIC_MAXPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.xmm[{}]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_XMM_VAL(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macro = (insn.mnemonic == ZYDIS_MNEMONIC_MINPS) ? "X86_SSE_MINPS" : "X86_SSE_MAXPS";
        println(fmt::format("\t{}(ctx.xmm[{}], {});", macro, d, srcExpr));
        break;
    }

    case ZYDIS_MNEMONIC_ANDNPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println(fmt::format("\tX86_SSE_ANDNPS(ctx.xmm[{}], ctx.xmm[{}]);", d, operands[1].reg.value - ZYDIS_REGISTER_XMM0));
        else
            println(fmt::format("\tX86_SSE_ANDNPS(ctx.xmm[{}], X86_MEM_READ_XMM_VAL(base, {}));",
                d, FormatMemOperand(insn, operands[1], address)));
        break;
    }

    case ZYDIS_MNEMONIC_CMPPS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.xmm[{}]", operands[1].reg.value - ZYDIS_REGISTER_XMM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_XMM_VAL(base, {})", FormatMemOperand(insn, operands[1], address));
        uint8_t imm = static_cast<uint8_t>(operands[2].imm.value.u);
        println(fmt::format("\tX86_SSE_CMPPS(ctx.xmm[{}], {}, {});", d, srcExpr, imm));
        break;
    }

    case ZYDIS_MNEMONIC_MOVMSKPS:
    {
        int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
        println(fmt::format("\t{} = ((ctx.xmm[{}].u32[0] >> 31)) | ((ctx.xmm[{}].u32[1] >> 31) << 1) | ((ctx.xmm[{}].u32[2] >> 31) << 2) | ((ctx.xmm[{}].u32[3] >> 31) << 3);",
            dst(), s, s, s, s));
        break;
    }

    // ---- MOVHPS ----
    case ZYDIS_MNEMONIC_MOVHPS:
    {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\tctx.xmm[{}].u64[1] = X86_MEM_READ_u64(base, {});", d, FormatMemOperand(insn, operands[1], address)));
        }
        else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\tX86_MEM_WRITE_u64(base, {}, ctx.xmm[{}].u64[1]);", FormatMemOperand(insn, operands[0], address), s));
        }
        break;
    }

    // ---- SSE<->MMX conversions ----
    case ZYDIS_MNEMONIC_CVTPS2PI:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
            println(fmt::format("\tctx.mm[{}].s32[0] = (int32_t)lrintf(ctx.xmm[{}].f32[0]);", d, s));
            println(fmt::format("\tctx.mm[{}].s32[1] = (int32_t)lrintf(ctx.xmm[{}].f32[1]);", d, s));
        }
        else
        {
            std::string ea = FormatMemOperand(insn, operands[1], address);
            println(fmt::format("\t{{ X86XmmReg _s; X86_MEM_READ_XMM(base, {}, _s);", ea));
            println(fmt::format("\t  ctx.mm[{}].s32[0] = (int32_t)lrintf(_s.f32[0]);", d));
            println(fmt::format("\t  ctx.mm[{}].s32[1] = (int32_t)lrintf(_s.f32[1]); }}", d));
        }
        break;
    }

    case ZYDIS_MNEMONIC_CVTPI2PS:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            int s = operands[1].reg.value - ZYDIS_REGISTER_MM0;
            println(fmt::format("\tctx.xmm[{}].f32[0] = (float)ctx.mm[{}].s32[0];", d, s));
            println(fmt::format("\tctx.xmm[{}].f32[1] = (float)ctx.mm[{}].s32[1];", d, s));
        }
        else
        {
            std::string ea = FormatMemOperand(insn, operands[1], address);
            println(fmt::format("\t{{ X86MmReg _s = X86_MEM_READ_MMX(base, {});", ea));
            println(fmt::format("\t  ctx.xmm[{}].f32[0] = (float)_s.s32[0];", d));
            println(fmt::format("\t  ctx.xmm[{}].f32[1] = (float)_s.s32[1]; }}", d));
        }
        break;
    }

    // ---- MMX: pandn, pcmp*, psraw, psrld, psllq, paddb, psubb, pmaxsw, pminsw, pavgb, pmovmskb, pinsrw ----
    case ZYDIS_MNEMONIC_PANDN:
    case ZYDIS_MNEMONIC_PCMPEQB: case ZYDIS_MNEMONIC_PCMPEQW: case ZYDIS_MNEMONIC_PCMPEQD:
    case ZYDIS_MNEMONIC_PCMPGTB: case ZYDIS_MNEMONIC_PCMPGTW: case ZYDIS_MNEMONIC_PCMPGTD:
    case ZYDIS_MNEMONIC_PADDB: case ZYDIS_MNEMONIC_PSUBB:
    case ZYDIS_MNEMONIC_PMAXSW: case ZYDIS_MNEMONIC_PMINSW:
    case ZYDIS_MNEMONIC_PAVGB:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string srcExpr;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcExpr = fmt::format("ctx.mm[{}]", operands[1].reg.value - ZYDIS_REGISTER_MM0);
        else
            srcExpr = fmt::format("X86_MEM_READ_MMX(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macro;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_PANDN:   macro = "X86_MMX_PANDN"; break;
        case ZYDIS_MNEMONIC_PCMPEQB: macro = "X86_MMX_PCMPEQB"; break;
        case ZYDIS_MNEMONIC_PCMPEQW: macro = "X86_MMX_PCMPEQW"; break;
        case ZYDIS_MNEMONIC_PCMPEQD: macro = "X86_MMX_PCMPEQD"; break;
        case ZYDIS_MNEMONIC_PCMPGTB: macro = "X86_MMX_PCMPGTB"; break;
        case ZYDIS_MNEMONIC_PCMPGTW: macro = "X86_MMX_PCMPGTW"; break;
        case ZYDIS_MNEMONIC_PCMPGTD: macro = "X86_MMX_PCMPGTD"; break;
        case ZYDIS_MNEMONIC_PADDB:   macro = "X86_MMX_PADDB"; break;
        case ZYDIS_MNEMONIC_PSUBB:   macro = "X86_MMX_PSUBB"; break;
        case ZYDIS_MNEMONIC_PMAXSW:  macro = "X86_MMX_PMAXSW"; break;
        case ZYDIS_MNEMONIC_PMINSW:  macro = "X86_MMX_PMINSW"; break;
        case ZYDIS_MNEMONIC_PAVGB:   macro = "X86_MMX_PAVGB"; break;
        default: macro = "X86_MMX_UNKNOWN"; break;
        }
        println(fmt::format("\t{}(ctx.mm[{}], {});", macro, d, srcExpr));
        break;
    }

    case ZYDIS_MNEMONIC_PSRAW: case ZYDIS_MNEMONIC_PSRLD: case ZYDIS_MNEMONIC_PSLLQ:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string cnt;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            cnt = fmt::format("{}", operands[1].imm.value.u);
        else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            cnt = fmt::format("(int)ctx.mm[{}].u64", operands[1].reg.value - ZYDIS_REGISTER_MM0);
        else
            cnt = fmt::format("(int)X86_MEM_READ_u64(base, {})", FormatMemOperand(insn, operands[1], address));
        const char* macro;
        switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_PSRAW: macro = "X86_MMX_PSRAW"; break;
        case ZYDIS_MNEMONIC_PSRLD: macro = "X86_MMX_PSRLD"; break;
        case ZYDIS_MNEMONIC_PSLLQ: macro = "X86_MMX_PSLLQ"; break;
        default: macro = "X86_MMX_UNKNOWN"; break;
        }
        println(fmt::format("\t{}(ctx.mm[{}], {});", macro, d, cnt));
        break;
    }

    case ZYDIS_MNEMONIC_PMOVMSKB:
    {
        int s = operands[1].reg.value - ZYDIS_REGISTER_MM0;
        println(fmt::format("\t{} = X86_MMX_PMOVMSKB(ctx.mm[{}]);", dst(), s));
        break;
    }

    case ZYDIS_MNEMONIC_PINSRW:
    {
        int d = operands[0].reg.value - ZYDIS_REGISTER_MM0;
        std::string srcVal;
        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            srcVal = CtxReg(operands[1].reg.value);
        else
            srcVal = fmt::format("X86_MEM_READ_u16(base, {})", FormatMemOperand(insn, operands[1], address));
        uint8_t imm = static_cast<uint8_t>(operands[2].imm.value.u) & 3;
        println(fmt::format("\tctx.mm[{}].u16[{}] = (uint16_t){};", d, imm, srcVal));
        break;
    }

    // ---- MOVNTQ ----
    case ZYDIS_MNEMONIC_MOVNTQ:
    {
        int s = operands[1].reg.value - ZYDIS_REGISTER_MM0;
        std::string ea = FormatMemOperand(insn, operands[0], address);
        println(fmt::format("\tX86_MEM_WRITE_u64(base, {}, ctx.mm[{}].u64);", ea, s));
        break;
    }

    // ---- PREFETCHT0 ----
    case ZYDIS_MNEMONIC_PREFETCHT0:
        println("\t// prefetcht0 - no-op");
        break;

    // ---- LDMXCSR / STMXCSR ----
    case ZYDIS_MNEMONIC_LDMXCSR:
        println("\t// ldmxcsr - ignored in recompilation");
        break;

    case ZYDIS_MNEMONIC_STMXCSR:
        println(fmt::format("\tX86_MEM_WRITE_u32(base, {}, 0x1F80);", FormatMemOperand(insn, operands[0], address)));
        break;

    // ---- Additional FPU ----
    case ZYDIS_MNEMONIC_FSINCOS:
        println("\t{ double _val = ctx.fp_stack[ctx.fp_top];");
        println("\t  ctx.fp_stack[ctx.fp_top] = X86_FPU_ROUND(ctx, sin(_val));");
        println("\t  X86_FPU_PUSH(ctx, cos(_val)); }");
        break;

    case ZYDIS_MNEMONIC_FINCSTP:
        println("\tctx.fp_top = (ctx.fp_top + 1) & 7;");
        break;

    case ZYDIS_MNEMONIC_FFREE:
        println("\t// ffree - no-op in recompilation");
        break;

    case ZYDIS_MNEMONIC_FCMOVNBE:
        println("\tif (!ctx.flags.cf && !ctx.flags.zf) ctx.fp_stack[ctx.fp_top] = ctx.fp_stack[" +
            fmt::format("(ctx.fp_top + {}) & 7", operands[1].reg.value - ZYDIS_REGISTER_ST0) + "];");
        break;

    case ZYDIS_MNEMONIC_FXTRACT:
        println("\t{ double _val = ctx.fp_stack[ctx.fp_top]; int _exp;");
        println("\t  double _sig = frexp(_val, &_exp);");
        println("\t  ctx.fp_stack[ctx.fp_top] = (double)(_exp - 1);");
        println("\t  X86_FPU_PUSH(ctx, ldexp(_sig, 1)); }");
        break;

    // ---- PUSHAD ----
    case ZYDIS_MNEMONIC_PUSHAD:
        println("\t{ uint32_t _esp = ctx.esp;");
        println("\t  ctx.esp -= 32;");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 4,  ctx.eax);");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 8,  ctx.ecx);");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 12, ctx.edx);");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 16, ctx.ebx);");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 20, _esp);");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 24, ctx.ebp);");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 28, ctx.esi);");
        println("\t  X86_MEM_WRITE_u32(base, _esp - 32, ctx.edi); }");
        break;

    default:
        println("\t// TODO: unimplemented instruction");
        return false;
    }

    return true;
}

// =====================================================================
// Per-function recompilation
// =====================================================================

void XBERecompiler::RecompileFunction(const Symbol& symbol)
{
    uint32_t funcAddr = static_cast<uint32_t>(symbol.address);
    uint32_t funcSize = static_cast<uint32_t>(symbol.size);

    if (funcSize == 0)
        return;

    const uint8_t* codeData = static_cast<const uint8_t*>(image.Find(funcAddr));
    if (!codeData)
        return;

    // Build list of all code regions (main body + chunks)
    curFuncBase = funcAddr;
    funcRegions.clear();
    funcRegions.push_back({ funcAddr, funcSize });

    auto funcIt = config.functions.find(funcAddr);
    if (funcIt != config.functions.end())
    {
        for (auto& chunk : funcIt->second.chunks)
        {
            if (image.Find(chunk.address))
                funcRegions.push_back({ chunk.address, chunk.size });
        }
    }

    // Pre-scan: map each switch table's base to the actual JMP instruction address.
    // The TOML 'base' may be the CMP (start of the switch block) or the JMP itself.
    // Two-pass approach: direct matches first (base IS a JMP), then scan for the rest
    // skipping already-claimed JMP addresses.
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, XBERecompSwitchTable>::iterator> switchJmpMap;
    std::set<uint32_t> claimedJmps;

    // Pass A: Direct matches — base address is itself the memory-indirect JMP
    for (auto it = config.switchTables.begin(); it != config.switchTables.end(); ++it)
    {
        uint32_t stBase = it->first;
        if (!IsLocalAddress(stBase))
            continue;

        const uint8_t* regionData = static_cast<const uint8_t*>(image.Find(stBase));
        if (!regionData) continue;

        ZydisDecodedInstruction scanInsn;
        ZydisDecodedOperand scanOps[ZYDIS_MAX_OPERAND_COUNT];
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
            regionData, 15, &scanInsn, scanOps)) &&
            scanInsn.mnemonic == ZYDIS_MNEMONIC_JMP &&
            scanOps[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            switchJmpMap[stBase] = it;
            claimedJmps.insert(stBase);
        }
    }

    // Pass B: Non-direct — scan forward from base within the same region to find a matching indirect JMP.
    for (auto it = config.switchTables.begin(); it != config.switchTables.end(); ++it)
    {
        uint32_t stBase = it->first;
        if (!IsLocalAddress(stBase))
            continue;
        if (claimedJmps.count(stBase))
            continue;

        // Find which region contains this base
        for (auto& region : funcRegions)
        {
            if (stBase < region.address || stBase >= region.address + region.size)
                continue;

            const uint8_t* regionData = static_cast<const uint8_t*>(image.Find(region.address));
            if (!regionData) break;

            uint32_t scanOffset = stBase - region.address;
            while (scanOffset < region.size)
            {
                ZydisDecodedInstruction scanInsn;
                ZydisDecodedOperand scanOps[ZYDIS_MAX_OPERAND_COUNT];
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
                    regionData + scanOffset, region.size - scanOffset, &scanInsn, scanOps)))
                {
                    scanOffset++;
                    continue;
                }
                uint32_t scanAddr = region.address + scanOffset;
                if (scanInsn.mnemonic == ZYDIS_MNEMONIC_JMP &&
                    scanOps[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    !claimedJmps.count(scanAddr))
                {
                    uint32_t tableAddr = static_cast<uint32_t>(scanOps[0].mem.disp.value);
                    const void* tableData = image.Find(tableAddr);
                    if (tableData && !it->second.labels.empty())
                    {
                        uint32_t firstEntry = *static_cast<const uint32_t*>(tableData);
                        if (firstEntry == it->second.labels[0])
                        {
                            switchJmpMap[scanAddr] = it;
                            claimedJmps.insert(scanAddr);
                            goto nextSwitch;
                        }
                    }
                }
                scanOffset += scanInsn.length;
            }
            break;
        }
        nextSwitch:;
    }

    // Pass 1: Collect labels (branch targets inside this function)
    std::set<uint32_t> labels;
    for (auto& region : funcRegions)
    {
        const uint8_t* regionData = static_cast<const uint8_t*>(image.Find(region.address));
        if (!regionData) continue;

        uint32_t offset = 0;
        while (offset < region.size)
        {
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
                regionData + offset, region.size - offset, &insn, operands)))
            {
                offset++;
                continue;
            }

            uint32_t addr = region.address + offset;

            if (insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE &&
                insn.operand_count_visible > 0 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = static_cast<uint32_t>(addr + insn.length + operands[0].imm.value.s);
                if (IsLocalAddress(target))
                    labels.insert(target);
            }

            auto switchIt = switchJmpMap.find(addr);
            if (switchIt != switchJmpMap.end())
            {
                for (auto lbl : switchIt->second->second.labels)
                {
                    uint32_t l = static_cast<uint32_t>(lbl);
                    if (IsLocalAddress(l))
                        labels.insert(l);
                }
            }

            offset += insn.length;
        }
    }

    // Pass 2: Emit the function
    tempOut.clear();

    println(fmt::format("void {}(X86Context& ctx, uint8_t* base) {{", symbol.name));

    int unimplemented = 0;
    for (size_t ri = 0; ri < funcRegions.size(); ri++)
    {
        auto& region = funcRegions[ri];
        const uint8_t* regionData = static_cast<const uint8_t*>(image.Find(region.address));
        if (!regionData) continue;

        // For chunks after the main body, emit a label so branches can reach them,
        // and add a separator comment
        if (ri > 0)
        {
            println(fmt::format("\t// ---- chunk at 0x{:X} (size 0x{:X}) ----", region.address, region.size));
            // If the chunk start isn't already a label from a branch, add one
            if (!labels.count(region.address))
                println(fmt::format("loc_{:X}:", region.address));
        }

        uint32_t offset = 0;
        while (offset < region.size)
        {
            uint32_t addr = region.address + offset;

            if (labels.count(addr))
                println(fmt::format("loc_{:X}:", addr));

            ZydisDecodedInstruction insn;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
                regionData + offset, region.size - offset, &insn, operands)))
            {
                println(fmt::format("\t// 0x{:X}: <invalid instruction>", addr));
                offset++;
                continue;
            }

            auto switchJmpIt = switchJmpMap.find(addr);
            auto switchIt = (switchJmpIt != switchJmpMap.end()) ? switchJmpIt->second : config.switchTables.end();
            if (!RecompileInstruction(addr, insn, operands, switchIt))
                unimplemented++;

            offset += insn.length;
        }
    }

    println("}");
    println("");

    out += tempOut;

    if (unimplemented > 0)
        fmt::println("  {} has {} unimplemented instructions", symbol.name, unimplemented);
}

// =====================================================================
// Recompile — top-level output generation
// =====================================================================

bool XBERecompiler::Recompile()
{
    std::string outDir = config.directoryPath;
    if (!outDir.empty()) outDir += "/";
    outDir += config.outDirectoryPath;

    std::filesystem::create_directories(outDir);

    out.reserve(4 * 1024 * 1024);

    auto saveFile = [&](const std::string& filename) {
        std::string filePath = outDir + "/" + filename;

        bool shouldWrite = true;
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (static_cast<size_t>(fileSize) == out.size())
            {
                fseek(f, 0, SEEK_SET);
                std::vector<uint8_t> temp(fileSize);
                fread(temp.data(), 1, fileSize, f);
                shouldWrite = !XXH128_isEqual(
                    XXH3_128bits(temp.data(), temp.size()),
                    XXH3_128bits(out.data(), out.size()));
            }
            fclose(f);
        }

        if (shouldWrite)
        {
            f = fopen(filePath.c_str(), "wb");
            if (f)
            {
                fwrite(out.data(), 1, out.size(), f);
                fclose(f);
                fmt::println("Written: {}", filePath);
            }
        }
        out.clear();
    };

    auto appendLine = [&](const std::string& line) {
        out += line;
        out += '\n';
    };

    // ---- Generate x86_config.h ----
    appendLine("#pragma once");
    appendLine("");
    appendLine(fmt::format("#define X86_IMAGE_BASE 0x{:X}ull", image.base));
    appendLine(fmt::format("#define X86_IMAGE_SIZE 0x{:X}ull", image.size));

    size_t codeMin = ~size_t(0);
    size_t codeMax = 0;
    for (auto& section : image.sections)
    {
        if (section.flags & SectionFlags_Code)
        {
            if (section.base < codeMin) codeMin = section.base;
            if ((section.base + section.size) > codeMax) codeMax = section.base + section.size;
        }
    }
    appendLine(fmt::format("#define X86_CODE_BASE 0x{:X}ull", codeMin));
    appendLine(fmt::format("#define X86_CODE_SIZE 0x{:X}ull", codeMax - codeMin));
    appendLine(fmt::format("#define X86_ENTRY_POINT 0x{:X}ull", image.entry_point));
    appendLine(fmt::format("#define X86_RAM_SIZE 0x{:X}ull", config.ramSize));
    appendLine("");

    saveFile("x86_config.h");

    // ---- Generate x86_context.h ----
    appendLine("#pragma once");
    appendLine("");
    appendLine("#include \"x86_config.h\"");
    appendLine("#include <cstdint>");
    appendLine("#include <cstring>");
    appendLine("#include <cmath>");
    appendLine("#include <limits>");
    appendLine("");
    appendLine("// ---- Sub-register access macros ----");
    appendLine("#define X86_REG16(r) (*(uint16_t*)&(r))");
    appendLine("#define X86_REG8L(r) (*(uint8_t*)&(r))");
    appendLine("#define X86_REG8H(r) (*((uint8_t*)&(r) + 1))");
    appendLine("");
    appendLine("// ---- Memory access macros (no byte-swap needed, x86-to-x86) ----");
    appendLine("#define X86_MEM_READ_u8(base, addr)   (*(uint8_t*)((base) + (uint32_t)(addr)))");
    appendLine("#define X86_MEM_READ_u16(base, addr)  (*(uint16_t*)((base) + (uint32_t)(addr)))");
    appendLine("#define X86_MEM_READ_u32(base, addr)  (*(uint32_t*)((base) + (uint32_t)(addr)))");
    appendLine("#define X86_MEM_READ_u64(base, addr)  (*(uint64_t*)((base) + (uint32_t)(addr)))");
    appendLine("#define X86_MEM_WRITE_u8(base, addr, v)  (*(uint8_t*)((base) + (uint32_t)(addr)) = (uint8_t)(v))");
    appendLine("#define X86_MEM_WRITE_u16(base, addr, v) (*(uint16_t*)((base) + (uint32_t)(addr)) = (uint16_t)(v))");
    appendLine("#define X86_MEM_WRITE_u32(base, addr, v) (*(uint32_t*)((base) + (uint32_t)(addr)) = (uint32_t)(v))");
    appendLine("#define X86_MEM_WRITE_u64(base, addr, v) (*(uint64_t*)((base) + (uint32_t)(addr)) = (uint64_t)(v))");
    appendLine("");
    appendLine("// ---- Floating-point memory access ----");
    appendLine("#define X86_MEM_READ_F32(base, addr)  (*(float*)((base) + (uint32_t)(addr)))");
    appendLine("#define X86_MEM_READ_F64(base, addr)  (*(double*)((base) + (uint32_t)(addr)))");
    appendLine("#define X86_MEM_WRITE_F32(base, addr, v) (*(float*)((base) + (uint32_t)(addr)) = (float)(v))");
    appendLine("#define X86_MEM_WRITE_F64(base, addr, v) (*(double*)((base) + (uint32_t)(addr)) = (double)(v))");
    appendLine("");
    appendLine("// ---- 80-bit extended precision FPU memory access ----");
    appendLine("inline double X86_MEM_READ_F80(uint8_t* base, uint32_t addr) {");
    appendLine("    uint8_t* p = base + addr;");
    appendLine("    uint64_t mantissa = *(uint64_t*)p;");
    appendLine("    uint16_t expsign = *(uint16_t*)(p + 8);");
    appendLine("    int sign = (expsign >> 15) & 1;");
    appendLine("    int exponent = expsign & 0x7FFF;");
    appendLine("    if (exponent == 0 && mantissa == 0) return sign ? -0.0 : 0.0;");
    appendLine("    if (exponent == 0x7FFF) {");
    appendLine("        if (mantissa & 0x7FFFFFFFFFFFFFFFull) return std::numeric_limits<double>::quiet_NaN();");
    appendLine("        return sign ? -std::numeric_limits<double>::infinity() : std::numeric_limits<double>::infinity();");
    appendLine("    }");
    appendLine("    double val = (double)mantissa / (double)(1ull << 63);");
    appendLine("    val = std::ldexp(val, exponent - 16383);");
    appendLine("    return sign ? -val : val;");
    appendLine("}");
    appendLine("inline void X86_MEM_WRITE_F80(uint8_t* base, uint32_t addr, double v) {");
    appendLine("    uint8_t* p = base + addr;");
    appendLine("    uint16_t expsign = 0;");
    appendLine("    uint64_t mantissa = 0;");
    appendLine("    if (v == 0.0) {");
    appendLine("        if (std::signbit(v)) expsign = 0x8000;");
    appendLine("    } else if (std::isinf(v)) {");
    appendLine("        expsign = std::signbit(v) ? 0xFFFF : 0x7FFF;");
    appendLine("        mantissa = 0x8000000000000000ull;");
    appendLine("    } else if (std::isnan(v)) {");
    appendLine("        expsign = 0x7FFF;");
    appendLine("        mantissa = 0xC000000000000000ull;");
    appendLine("    } else {");
    appendLine("        if (v < 0) { expsign = 0x8000; v = -v; }");
    appendLine("        int exp;");
    appendLine("        double frac = std::frexp(v, &exp);");
    appendLine("        expsign |= (uint16_t)(exp + 16382);");
    appendLine("        mantissa = (uint64_t)(frac * (double)(1ull << 63)) | 0x8000000000000000ull;");
    appendLine("    }");
    appendLine("    *(uint64_t*)p = mantissa;");
    appendLine("    *(uint16_t*)(p + 8) = expsign;");
    appendLine("}");
    appendLine("");
    appendLine("// ---- MMX register type ----");
    appendLine("struct X86MmReg {");
    appendLine("    union {");
    appendLine("        uint64_t u64;");
    appendLine("        int64_t s64;");
    appendLine("        uint32_t u32[2];");
    appendLine("        int32_t s32[2];");
    appendLine("        uint16_t u16[4];");
    appendLine("        int16_t s16[4];");
    appendLine("        uint8_t u8[8];");
    appendLine("        int8_t s8[8];");
    appendLine("    };");
    appendLine("};");
    appendLine("");
    appendLine("inline X86MmReg X86_MEM_READ_MMX(uint8_t* base, uint32_t addr) { X86MmReg r; r.u64 = *(uint64_t*)(base + addr); return r; }");
    appendLine("");
    appendLine("// ---- MMX packed operations ----");
    appendLine("inline void X86_MMX_PADDW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) d.u16[i] += s.u16[i]; }");
    appendLine("inline void X86_MMX_PADDD(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<2;i++) d.u32[i] += s.u32[i]; }");
    appendLine("inline void X86_MMX_PSUBW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) d.u16[i] -= s.u16[i]; }");
    appendLine("inline void X86_MMX_PSUBD(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<2;i++) d.u32[i] -= s.u32[i]; }");
    appendLine("inline void X86_MMX_PSUBSW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) { int32_t r = (int32_t)d.s16[i] - (int32_t)s.s16[i]; d.s16[i] = r < -32768 ? -32768 : (r > 32767 ? 32767 : (int16_t)r); } }");
    appendLine("inline void X86_MMX_PMULLW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) d.s16[i] = (int16_t)((int32_t)d.s16[i] * (int32_t)s.s16[i]); }");
    appendLine("inline void X86_MMX_PMADDWD(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<2;i++) d.s32[i] = (int32_t)d.s16[i*2] * (int32_t)s.s16[i*2] + (int32_t)d.s16[i*2+1] * (int32_t)s.s16[i*2+1]; }");
    appendLine("inline void X86_MMX_PXOR(X86MmReg& d, const X86MmReg& s) { d.u64 ^= s.u64; }");
    appendLine("inline void X86_MMX_PAND(X86MmReg& d, const X86MmReg& s) { d.u64 &= s.u64; }");
    appendLine("inline void X86_MMX_POR(X86MmReg& d, const X86MmReg& s) { d.u64 |= s.u64; }");
    appendLine("inline void X86_MMX_PSLLW(X86MmReg& d, int cnt) { if(cnt>=16) d.u64=0; else for(int i=0;i<4;i++) d.u16[i] <<= cnt; }");
    appendLine("inline void X86_MMX_PSLLD(X86MmReg& d, int cnt) { if(cnt>=32) d.u64=0; else for(int i=0;i<2;i++) d.u32[i] <<= cnt; }");
    appendLine("inline void X86_MMX_PSRLW(X86MmReg& d, int cnt) { if(cnt>=16) d.u64=0; else for(int i=0;i<4;i++) d.u16[i] >>= cnt; }");
    appendLine("inline void X86_MMX_PSRLQ(X86MmReg& d, int cnt) { d.u64 = cnt >= 64 ? 0 : d.u64 >> cnt; }");
    appendLine("inline void X86_MMX_PSRAD(X86MmReg& d, int cnt) { for(int i=0;i<2;i++) d.s32[i] = cnt >= 32 ? (d.s32[i] >> 31) : d.s32[i] >> cnt; }");
    appendLine("inline void X86_MMX_PUNPCKLBW(X86MmReg& d, const X86MmReg& s) { X86MmReg t; for(int i=0;i<4;i++) { t.u8[i*2]=d.u8[i]; t.u8[i*2+1]=s.u8[i]; } d=t; }");
    appendLine("inline void X86_MMX_PUNPCKHBW(X86MmReg& d, const X86MmReg& s) { X86MmReg t; for(int i=0;i<4;i++) { t.u8[i*2]=d.u8[i+4]; t.u8[i*2+1]=s.u8[i+4]; } d=t; }");
    appendLine("inline void X86_MMX_PUNPCKLWD(X86MmReg& d, const X86MmReg& s) { X86MmReg t; for(int i=0;i<2;i++) { t.u16[i*2]=d.u16[i]; t.u16[i*2+1]=s.u16[i]; } d=t; }");
    appendLine("inline void X86_MMX_PUNPCKHWD(X86MmReg& d, const X86MmReg& s) { X86MmReg t; for(int i=0;i<2;i++) { t.u16[i*2]=d.u16[i+2]; t.u16[i*2+1]=s.u16[i+2]; } d=t; }");
    appendLine("inline void X86_MMX_PUNPCKLDQ(X86MmReg& d, const X86MmReg& s) { d.u32[1]=s.u32[0]; }");
    appendLine("inline void X86_MMX_PUNPCKHDQ(X86MmReg& d, const X86MmReg& s) { X86MmReg t; t.u32[0]=d.u32[1]; t.u32[1]=s.u32[1]; d=t; }");
    appendLine("inline void X86_MMX_PACKSSDW(X86MmReg& d, const X86MmReg& s) { X86MmReg t; t.s16[0]=d.s32[0]<-32768?-32768:(d.s32[0]>32767?32767:(int16_t)d.s32[0]); t.s16[1]=d.s32[1]<-32768?-32768:(d.s32[1]>32767?32767:(int16_t)d.s32[1]); t.s16[2]=s.s32[0]<-32768?-32768:(s.s32[0]>32767?32767:(int16_t)s.s32[0]); t.s16[3]=s.s32[1]<-32768?-32768:(s.s32[1]>32767?32767:(int16_t)s.s32[1]); d=t; }");
    appendLine("inline void X86_MMX_PACKUSWB(X86MmReg& d, const X86MmReg& s) { X86MmReg t; for(int i=0;i<4;i++) t.u8[i]=(uint8_t)(d.s16[i]<0?0:(d.s16[i]>255?255:d.s16[i])); for(int i=0;i<4;i++) t.u8[i+4]=(uint8_t)(s.s16[i]<0?0:(s.s16[i]>255?255:s.s16[i])); d=t; }");
    appendLine("inline void X86_MMX_PACKSSWB(X86MmReg& d, const X86MmReg& s) { X86MmReg t; for(int i=0;i<4;i++) t.s8[i]=(int8_t)(d.s16[i]<-128?-128:(d.s16[i]>127?127:d.s16[i])); for(int i=0;i<4;i++) t.s8[i+4]=(int8_t)(s.s16[i]<-128?-128:(s.s16[i]>127?127:s.s16[i])); d=t; }");
    appendLine("inline void X86_MMX_PSHUFW(X86MmReg& d, const X86MmReg& s, uint8_t imm) { X86MmReg t; t.u16[0]=s.u16[imm&3]; t.u16[1]=s.u16[(imm>>2)&3]; t.u16[2]=s.u16[(imm>>4)&3]; t.u16[3]=s.u16[(imm>>6)&3]; d=t; }");
    appendLine("inline void X86_MMX_PANDN(X86MmReg& d, const X86MmReg& s) { d.u64 = ~d.u64 & s.u64; }");
    appendLine("inline void X86_MMX_PCMPEQB(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<8;i++) d.u8[i] = (d.u8[i]==s.u8[i]) ? 0xFF : 0; }");
    appendLine("inline void X86_MMX_PCMPEQW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) d.u16[i] = (d.u16[i]==s.u16[i]) ? 0xFFFF : 0; }");
    appendLine("inline void X86_MMX_PCMPEQD(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<2;i++) d.u32[i] = (d.u32[i]==s.u32[i]) ? 0xFFFFFFFFu : 0; }");
    appendLine("inline void X86_MMX_PCMPGTB(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<8;i++) d.u8[i] = (d.s8[i]>s.s8[i]) ? 0xFF : 0; }");
    appendLine("inline void X86_MMX_PCMPGTW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) d.u16[i] = (d.s16[i]>s.s16[i]) ? 0xFFFF : 0; }");
    appendLine("inline void X86_MMX_PCMPGTD(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<2;i++) d.u32[i] = (d.s32[i]>s.s32[i]) ? 0xFFFFFFFFu : 0; }");
    appendLine("inline void X86_MMX_PADDB(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<8;i++) d.u8[i] += s.u8[i]; }");
    appendLine("inline void X86_MMX_PSUBB(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<8;i++) d.u8[i] -= s.u8[i]; }");
    appendLine("inline void X86_MMX_PSRAW(X86MmReg& d, int cnt) { for(int i=0;i<4;i++) d.s16[i] = cnt >= 16 ? (d.s16[i] >> 15) : d.s16[i] >> cnt; }");
    appendLine("inline void X86_MMX_PSRLD(X86MmReg& d, int cnt) { if(cnt>=32) d.u64=0; else for(int i=0;i<2;i++) d.u32[i] >>= cnt; }");
    appendLine("inline void X86_MMX_PSLLQ(X86MmReg& d, int cnt) { d.u64 = cnt >= 64 ? 0 : d.u64 << cnt; }");
    appendLine("inline void X86_MMX_PMAXSW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) if(s.s16[i]>d.s16[i]) d.s16[i]=s.s16[i]; }");
    appendLine("inline void X86_MMX_PMINSW(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<4;i++) if(s.s16[i]<d.s16[i]) d.s16[i]=s.s16[i]; }");
    appendLine("inline void X86_MMX_PAVGB(X86MmReg& d, const X86MmReg& s) { for(int i=0;i<8;i++) d.u8[i] = (uint8_t)(((uint16_t)d.u8[i] + (uint16_t)s.u8[i] + 1) >> 1); }");
    appendLine("inline uint32_t X86_MMX_PMOVMSKB(const X86MmReg& s) { uint32_t r=0; for(int i=0;i<8;i++) r |= ((s.u8[i]>>7)<<i); return r; }");
    appendLine("");
    appendLine("// ---- XMM memory access ----");
    appendLine("struct X86XmmReg {");
    appendLine("    union {");
    appendLine("        float f32[4];");
    appendLine("        double f64[2];");
    appendLine("        uint32_t u32[4];");
    appendLine("        int32_t s32[4];");
    appendLine("        uint64_t u64[2];");
    appendLine("        uint8_t u8[16];");
    appendLine("    };");
    appendLine("};");
    appendLine("");
    appendLine("#define X86_MEM_READ_XMM(base, addr, dst)  memcpy(&(dst), (base) + (uint32_t)(addr), 16)");
    appendLine("#define X86_MEM_WRITE_XMM(base, addr, src) memcpy((base) + (uint32_t)(addr), &(src), 16)");
    appendLine("inline X86XmmReg X86_MEM_READ_XMM_VAL(uint8_t* base, uint32_t addr) { X86XmmReg r; memcpy(&r, base + addr, 16); return r; }");
    appendLine("");
    appendLine("// ---- SSE packed operations ----");
    appendLine("#define X86_SSE_ADDPS(d, s) do { for (int _i=0;_i<4;_i++) (d).f32[_i] += (s).f32[_i]; } while(0)");
    appendLine("#define X86_SSE_SUBPS(d, s) do { for (int _i=0;_i<4;_i++) (d).f32[_i] -= (s).f32[_i]; } while(0)");
    appendLine("#define X86_SSE_MULPS(d, s) do { for (int _i=0;_i<4;_i++) (d).f32[_i] *= (s).f32[_i]; } while(0)");
    appendLine("#define X86_SSE_DIVPS(d, s) do { for (int _i=0;_i<4;_i++) (d).f32[_i] /= (s).f32[_i]; } while(0)");
    appendLine("#define X86_SSE_XORPS(d, s) do { for (int _i=0;_i<4;_i++) (d).u32[_i] ^= (s).u32[_i]; } while(0)");
    appendLine("#define X86_SSE_ANDPS(d, s) do { for (int _i=0;_i<4;_i++) (d).u32[_i] &= (s).u32[_i]; } while(0)");
    appendLine("#define X86_SSE_ORPS(d, s)  do { for (int _i=0;_i<4;_i++) (d).u32[_i] |= (s).u32[_i]; } while(0)");
    appendLine("#define X86_SSE_ANDNPS(d, s) do { for (int _i=0;_i<4;_i++) (d).u32[_i] = ~(d).u32[_i] & (s).u32[_i]; } while(0)");
    appendLine("#define X86_SSE_MINPS(d, s) do { for (int _i=0;_i<4;_i++) (d).f32[_i] = fminf((d).f32[_i], (s).f32[_i]); } while(0)");
    appendLine("#define X86_SSE_MAXPS(d, s) do { for (int _i=0;_i<4;_i++) (d).f32[_i] = fmaxf((d).f32[_i], (s).f32[_i]); } while(0)");
    appendLine("#define X86_SSE_CMPPS(d, s, imm) do { for (int _i=0;_i<4;_i++) { \\");
    appendLine("    bool _r; float _a = (d).f32[_i], _b = (s).f32[_i]; \\");
    appendLine("    switch ((imm)&7) { case 0:_r=_a==_b;break; case 1:_r=_a<_b;break; case 2:_r=_a<=_b;break; case 3:_r=_a!=_b;break; \\");
    appendLine("    case 4:_r=_a!=_b;break; case 5:_r=_a>=_b;break; case 6:_r=_a>_b;break; default:_r=_a==_b;break; } \\");
    appendLine("    (d).u32[_i] = _r ? 0xFFFFFFFFu : 0u; } } while(0)");
    appendLine("");
    appendLine("// ---- SSE scalar compare -> EFLAGS ----");
    appendLine("inline void X86_SSE_COMPARE_EFLAGS(struct X86Context& ctx, float a, float b);");
    appendLine("");
    appendLine("// ---- Flags ----");
    appendLine("struct X86Flags {");
    appendLine("    uint8_t cf; // carry");
    appendLine("    uint8_t pf; // parity");
    appendLine("    uint8_t af; // adjust");
    appendLine("    uint8_t zf; // zero");
    appendLine("    uint8_t sf; // sign");
    appendLine("    uint8_t of; // overflow");
    appendLine("    uint8_t df; // direction");
    appendLine("};");
    appendLine("");
    appendLine("// ---- FPU state ----");
    appendLine("#define X86_FPU_STACK_SIZE 8");
    appendLine("");
    appendLine("// ---- Context ----");
    appendLine("struct X86Context {");
    appendLine("    // General-purpose registers");
    appendLine("    uint32_t eax, ecx, edx, ebx;");
    appendLine("    uint32_t esp, ebp, esi, edi;");
    appendLine("    // Flags");
    appendLine("    X86Flags flags;");
    appendLine("    // FPU");
    appendLine("    double fp_stack[X86_FPU_STACK_SIZE];");
    appendLine("    int fp_top;");
    appendLine("    uint16_t fp_control;");
    appendLine("    uint16_t fp_status;");
    appendLine("    // SSE");
    appendLine("    X86XmmReg xmm[8];");
    appendLine("    // MMX");
    appendLine("    X86MmReg mm[8];");
    appendLine("};");
    appendLine("");
    appendLine("// ---- Flags helpers ----");
    appendLine("inline uint8_t x86_parity(uint8_t v) {");
    appendLine("    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1; return (~v) & 1;");
    appendLine("}");
    appendLine("");
    appendLine("#define X86_UPDATE_FLAGS_ARITH(ctx, result, bits) do { \\");
    appendLine("    (ctx).flags.zf = ((result) & ((1ull << (bits)) - 1)) == 0; \\");
    appendLine("    (ctx).flags.sf = ((result) >> ((bits) - 1)) & 1; \\");
    appendLine("    (ctx).flags.pf = x86_parity((uint8_t)(result)); \\");
    appendLine("} while(0)");
    appendLine("");
    appendLine("#define X86_UPDATE_FLAGS_LOGIC(ctx, result, bits) do { \\");
    appendLine("    (ctx).flags.cf = 0; \\");
    appendLine("    (ctx).flags.of = 0; \\");
    appendLine("    (ctx).flags.zf = ((result) & ((1ull << (bits)) - 1)) == 0; \\");
    appendLine("    (ctx).flags.sf = ((result) >> ((bits) - 1)) & 1; \\");
    appendLine("    (ctx).flags.pf = x86_parity((uint8_t)(result)); \\");
    appendLine("} while(0)");
    appendLine("");
    appendLine("#define X86_UPDATE_FLAGS_ADD(ctx, result64, sd, ss, bits) do { \\");
    appendLine("    auto _mask = (uint64_t)((1ull << (bits)) - 1); \\");
    appendLine("    (ctx).flags.cf = ((result64) >> (bits)) & 1; \\");
    appendLine("    (ctx).flags.zf = ((result64) & _mask) == 0; \\");
    appendLine("    (ctx).flags.sf = ((result64) >> ((bits) - 1)) & 1; \\");
    appendLine("    (ctx).flags.of = ((~((sd) ^ (ss))) & ((sd) ^ (result64))) >> ((bits) - 1) & 1; \\");
    appendLine("    (ctx).flags.pf = x86_parity((uint8_t)(result64)); \\");
    appendLine("} while(0)");
    appendLine("");
    appendLine("#define X86_UPDATE_FLAGS_SUB(ctx, result64, sd, ss, bits) do { \\");
    appendLine("    auto _mask = (uint64_t)((1ull << (bits)) - 1); \\");
    appendLine("    (ctx).flags.cf = ((result64) >> (bits)) & 1; \\");
    appendLine("    (ctx).flags.zf = ((result64) & _mask) == 0; \\");
    appendLine("    (ctx).flags.sf = ((result64) >> ((bits) - 1)) & 1; \\");
    appendLine("    (ctx).flags.of = (((sd) ^ (ss)) & ((sd) ^ (result64))) >> ((bits) - 1) & 1; \\");
    appendLine("    (ctx).flags.pf = x86_parity((uint8_t)(result64)); \\");
    appendLine("} while(0)");
    appendLine("");
    appendLine("#define X86_UPDATE_FLAGS_INC(ctx, result64, sd, bits) do { \\");
    appendLine("    (ctx).flags.zf = ((result64) & ((1ull << (bits)) - 1)) == 0; \\");
    appendLine("    (ctx).flags.sf = ((result64) >> ((bits) - 1)) & 1; \\");
    appendLine("    (ctx).flags.of = (((sd) ^ (result64)) & ~(sd)) >> ((bits) - 1) & 1; \\");
    appendLine("    (ctx).flags.pf = x86_parity((uint8_t)(result64)); \\");
    appendLine("} while(0)");
    appendLine("");
    appendLine("#define X86_UPDATE_FLAGS_DEC(ctx, result64, sd, bits) do { \\");
    appendLine("    (ctx).flags.zf = ((result64) & ((1ull << (bits)) - 1)) == 0; \\");
    appendLine("    (ctx).flags.sf = ((result64) >> ((bits) - 1)) & 1; \\");
    appendLine("    (ctx).flags.of = ((sd) & ~(result64)) >> ((bits) - 1) & 1; \\");
    appendLine("    (ctx).flags.pf = x86_parity((uint8_t)(result64)); \\");
    appendLine("} while(0)");
    appendLine("");
    appendLine("// ---- Bit operations ----");
    appendLine("#ifdef _MSC_VER");
    appendLine("#include <intrin.h>");
    appendLine("inline uint32_t X86_BSF(int bits, uint32_t val) { unsigned long idx; _BitScanForward(&idx, val); return idx; }");
    appendLine("inline uint32_t X86_BSR(int bits, uint32_t val) { unsigned long idx; _BitScanReverse(&idx, val); return idx; }");
    appendLine("#else");
    appendLine("inline uint32_t X86_BSF(int bits, uint32_t val) { return __builtin_ctz(val); }");
    appendLine("inline uint32_t X86_BSR(int bits, uint32_t val) { return 31 - __builtin_clz(val); }");
    appendLine("#endif");
    appendLine("");
    appendLine("// ---- LAHF/SAHF ----");
    appendLine("inline uint8_t X86_PACK_FLAGS_AH(X86Context& ctx) {");
    appendLine("    return (ctx.flags.sf << 7) | (ctx.flags.zf << 6) | (ctx.flags.af << 4) | (ctx.flags.pf << 2) | (1 << 1) | ctx.flags.cf;");
    appendLine("}");
    appendLine("inline void X86_UNPACK_FLAGS_AH(X86Context& ctx, uint8_t ah) {");
    appendLine("    ctx.flags.sf = (ah >> 7) & 1; ctx.flags.zf = (ah >> 6) & 1;");
    appendLine("    ctx.flags.af = (ah >> 4) & 1; ctx.flags.pf = (ah >> 2) & 1; ctx.flags.cf = ah & 1;");
    appendLine("}");
    appendLine("");
    appendLine("// ---- FPU helpers ----");
    appendLine("inline double X86_FPU_ROUND(const X86Context& ctx, double v) {");
    appendLine("    switch ((ctx.fp_control >> 8) & 3) {");
    appendLine("        case 0:  return (double)(float)v;  // PC=00, single");
    appendLine("        case 2:  return v;                 // PC=10, double");
    appendLine("        default: return v;                 // PC=11 / PC=01, extended or reserved");
    appendLine("    }");
    appendLine("}");
    appendLine("");
    appendLine("#define X86_FPU_PUSH(ctx, val) do { \\");
    appendLine("    double _v = X86_FPU_ROUND((ctx), (val)); \\");
    appendLine("    (ctx).fp_top = ((ctx).fp_top - 1) & 7; \\");
    appendLine("    (ctx).fp_stack[(ctx).fp_top] = _v; \\");
    appendLine("} while(0)");
    appendLine("#define X86_FPU_POP(ctx) do { (ctx).fp_top = ((ctx).fp_top + 1) & 7; } while(0)");
    appendLine("");
    appendLine("inline void X86_FPU_COMPARE(X86Context& ctx, double a, double b) {");
    appendLine("    ctx.fp_status &= ~0x4500;");
    appendLine("    if (a > b) { }");
    appendLine("    else if (a < b) { ctx.fp_status |= 0x0100; }");
    appendLine("    else if (a == b) { ctx.fp_status |= 0x4000; }");
    appendLine("    else { ctx.fp_status |= 0x4500; }");
    appendLine("}");
    appendLine("");
    appendLine("inline void X86_FPU_COMPARE_EFLAGS(X86Context& ctx, double a, double b) {");
    appendLine("    ctx.flags.cf = 0; ctx.flags.zf = 0; ctx.flags.pf = 0;");
    appendLine("    if (a > b) { }");
    appendLine("    else if (a < b) { ctx.flags.cf = 1; }");
    appendLine("    else if (a == b) { ctx.flags.zf = 1; }");
    appendLine("    else { ctx.flags.cf = 1; ctx.flags.zf = 1; ctx.flags.pf = 1; }");
    appendLine("}");
    appendLine("");
    appendLine("inline void X86_SSE_COMPARE_EFLAGS(X86Context& ctx, float a, float b) {");
    appendLine("    ctx.flags.cf = 0; ctx.flags.zf = 0; ctx.flags.pf = 0;");
    appendLine("    if (a > b) { }");
    appendLine("    else if (a < b) { ctx.flags.cf = 1; }");
    appendLine("    else if (a == b) { ctx.flags.zf = 1; }");
    appendLine("    else { ctx.flags.cf = 1; ctx.flags.zf = 1; ctx.flags.pf = 1; }");
    appendLine("}");
    appendLine("");
    appendLine("inline uint16_t X86_FPU_STATUS(X86Context& ctx) { return ctx.fp_status; }");
    appendLine("");
    appendLine("// ---- EFLAGS pack/unpack for PUSHFD/POPFD ----");
    appendLine("inline uint32_t X86_PACK_EFLAGS(X86Context& ctx) {");
    appendLine("    return (uint32_t)ctx.flags.cf | (1u << 1) | ((uint32_t)ctx.flags.pf << 2) | ((uint32_t)ctx.flags.af << 4) |");
    appendLine("           ((uint32_t)ctx.flags.zf << 6) | ((uint32_t)ctx.flags.sf << 7) | ((uint32_t)ctx.flags.df << 10) | ((uint32_t)ctx.flags.of << 11);");
    appendLine("}");
    appendLine("inline void X86_UNPACK_EFLAGS(X86Context& ctx, uint32_t fl) {");
    appendLine("    ctx.flags.cf = fl & 1; ctx.flags.pf = (fl >> 2) & 1; ctx.flags.af = (fl >> 4) & 1;");
    appendLine("    ctx.flags.zf = (fl >> 6) & 1; ctx.flags.sf = (fl >> 7) & 1; ctx.flags.df = (fl >> 10) & 1; ctx.flags.of = (fl >> 11) & 1;");
    appendLine("}");
    appendLine("");
    appendLine("// ---- CPUID stub ----");
    appendLine("inline void X86_CPUID(X86Context& ctx) {");
    appendLine("    switch (ctx.eax) {");
    appendLine("    case 0: ctx.eax = 1; ctx.ebx = 0x756E6547; ctx.edx = 0x49656E69; ctx.ecx = 0x6C65746E; break;");
    appendLine("    case 1: ctx.eax = 0x00000686; ctx.ebx = 0; ctx.ecx = 0; ctx.edx = 0x0383FBFF; break;");
    appendLine("    default: ctx.eax = 0; ctx.ebx = 0; ctx.ecx = 0; ctx.edx = 0; break;");
    appendLine("    }");
    appendLine("}");
    appendLine("");
    appendLine("// ---- RDTSC ----");
    appendLine("#ifdef _MSC_VER");
    appendLine("#include <intrin.h>");
    appendLine("inline uint64_t X86_RDTSC() { return __rdtsc(); }");
    appendLine("#else");
    appendLine("inline uint64_t X86_RDTSC() { uint32_t lo, hi; __asm__ volatile(\"rdtsc\" : \"=a\"(lo), \"=d\"(hi)); return ((uint64_t)hi << 32) | lo; }");
    appendLine("#endif");
    appendLine("");
    appendLine("// ---- Recompiled function signature ----");
    appendLine("typedef void (*X86RecompFunc)(X86Context& ctx, uint8_t* base);");
    appendLine("");
    appendLine("// ---- Indirect call/jump (dispatch through function table) ----");
    appendLine("#include <unordered_map>");
    appendLine("#include <cstdio>");
    appendLine("extern std::unordered_map<uint32_t, X86RecompFunc> g_funcMap;");
    appendLine("void X86_CALL_INDIRECT(X86Context& ctx, uint8_t* base, uint32_t addr);");
    appendLine("void X86_JMP_INDIRECT(X86Context& ctx, uint8_t* base, uint32_t addr);");
    appendLine("");

    saveFile("x86_context.h");

    // ---- Generate x86_recomp_shared.h ----
    appendLine("#pragma once");
    appendLine("#include \"x86_context.h\"");
    appendLine("");

    for (auto& symbol : image.symbols)
    {
        if (symbol.type == Symbol_Function && symbol.size > 0)
            appendLine(fmt::format("extern void {}(X86Context& ctx, uint8_t* base);", symbol.name));
    }
    appendLine("");

    saveFile("x86_recomp_shared.h");

    // ---- Generate x86_func_mapping.cpp ----
    appendLine("#include \"x86_recomp_shared.h\"");
    appendLine("#include <unordered_map>");
    appendLine("#include <cstdio>");
    appendLine("");

    appendLine("std::unordered_map<uint32_t, X86RecompFunc> g_funcMap = {");
    for (auto& symbol : image.symbols)
    {
        if (symbol.type == Symbol_Function && symbol.size > 0)
            appendLine(fmt::format("    {{ 0x{:X}, {} }},", symbol.address, symbol.name));
    }
    appendLine("};");
    appendLine("");

    appendLine("void X86_CALL_INDIRECT(X86Context& ctx, uint8_t* base, uint32_t addr) {");
    appendLine("    auto it = g_funcMap.find(addr);");
    appendLine("    if (it != g_funcMap.end()) {");
    appendLine("        it->second(ctx, base);");
    appendLine("    } else {");
    appendLine("        static int s_missLog = 0;");
    appendLine("        if (s_missLog < 50) {");
    appendLine("            fprintf(stderr, \"[X86_CALL_INDIRECT] MISS: target 0x%08X not in g_funcMap!\\n\", addr);");
    appendLine("            s_missLog++;");
    appendLine("        }");
    appendLine("    }");
    appendLine("}");
    appendLine("");

    appendLine("void X86_JMP_INDIRECT(X86Context& ctx, uint8_t* base, uint32_t addr) {");
    appendLine("    auto it = g_funcMap.find(addr);");
    appendLine("    if (it != g_funcMap.end()) {");
    appendLine("        it->second(ctx, base);");
    appendLine("    } else {");
    appendLine("        fprintf(stderr, \"[X86_JMP_INDIRECT] target 0x%08X not found in g_funcMap!\\n\", addr);");
    appendLine("    }");
    appendLine("}");
    appendLine("");

    saveFile("x86_func_mapping.cpp");

    // ---- Generate x86_kernel_imports.h ----
    appendLine("#pragma once");
    appendLine("#include <cstdint>");
    appendLine("");
    for (auto& [addr, name] : hookedImports)
        appendLine(fmt::format("// 0x{:X} -> {}", addr, name));
    appendLine("");
    appendLine("struct XboxKernelImport {");
    appendLine("    uint32_t thunkAddr;");
    appendLine("    const char* name;");
    appendLine("};");
    appendLine("");
    appendLine("inline XboxKernelImport g_kernelImports[] = {");
    for (auto& [addr, name] : hookedImports)
        appendLine(fmt::format("    {{ 0x{:X}, \"{}\" }},", addr, name));
    appendLine("    { 0, nullptr }");
    appendLine("};");

    saveFile("x86_kernel_imports.h");

    // ---- Generate x86_switch_tables.h ----
    appendLine("#pragma once");
    appendLine("#include <cstdint>");
    appendLine("");
    for (auto& [base, table] : config.switchTables)
    {
        appendLine(fmt::format("// Switch table at 0x{:X} (reg={})", base, table.reg));
        appendLine(fmt::format("inline uint32_t g_switchTable_{:X}[] = {{", base));
        for (auto& label : table.labels)
            appendLine(fmt::format("    0x{:X},", label));
        appendLine("};");
        appendLine("");
    }

    saveFile("x86_switch_tables.h");

    // ---- Generate x86_recomp.N.cpp -- the actual recompiled code ----
    int cppFileIndex = 0;
    int funcInFile = 0;
    int totalRecompiled = 0;
    constexpr int FUNCS_PER_FILE = 256;

    auto startNewFile = [&]() {
        if (!out.empty()) saveFile(fmt::format("x86_recomp.{}.cpp", cppFileIndex++));
        out.clear();
        appendLine("#include \"x86_recomp_shared.h\"");
        appendLine("");
        funcInFile = 0;
    };

    startNewFile();

    for (auto& symbol : image.symbols)
    {
        if (symbol.type != Symbol_Function || symbol.size == 0)
            continue;

        if (hookedImports.count(static_cast<uint32_t>(symbol.address)))
            continue;

        if (funcInFile >= FUNCS_PER_FILE)
            startNewFile();

        RecompileFunction(symbol);
        funcInFile++;
        totalRecompiled++;
    }

    if (!out.empty())
        saveFile(fmt::format("x86_recomp.{}.cpp", cppFileIndex));

    fmt::println("Recompilation output generated in: {}", outDir);
    fmt::println("  {} functions recompiled into {} files", totalRecompiled, cppFileIndex + 1);
    fmt::println("  {} kernel imports", hookedImports.size());
    fmt::println("  {} switch tables", config.switchTables.size());

    return true;
}
