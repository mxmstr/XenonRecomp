#pragma once
#include "recompiler_config.h"
#include <image.h>
#include <string>
#include <vector>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <Zydis/Zydis.h>

struct XBERecompiler
{
    Image image;
    XBERecompConfig config;
    uint32_t kernelThunkAddr = 0;

    // Guest→host hook registry for kernel imports
    std::unordered_map<uint32_t, std::string> hookedImports;

    // Output buffer
    std::string out;
    std::string tempOut;

    // Disassembler
    ZydisDecoder decoder{};
    ZydisFormatter formatter{};

    // Current function regions (main body + chunks), set during RecompileFunction
    struct CodeRegion { uint32_t address; uint32_t size; };
    std::vector<CodeRegion> funcRegions;
    uint32_t curFuncBase = 0; // Entry point of current function

    bool IsLocalAddress(uint32_t addr) const;

    bool LoadConfig(const std::string_view& configFilePath);
    bool LoadXBE();
    void Analyse();
    bool HookKernelImports();
    bool Recompile();

    // Per-function recompilation
    void RecompileFunction(const Symbol& symbol);

    // Per-instruction recompilation
    bool RecompileInstruction(uint32_t address,
        const ZydisDecodedInstruction& insn,
        const ZydisDecodedOperand* operands,
        const std::unordered_map<uint32_t, XBERecompSwitchTable>::iterator& switchTable);

    // Helpers
    void print(const std::string& s);
    void println(const std::string& s);
    std::string FormatOperand(const ZydisDecodedInstruction& insn,
        const ZydisDecodedOperand& op, uint32_t address);
    std::string FormatMemOperand(const ZydisDecodedInstruction& insn,
        const ZydisDecodedOperand& op, uint32_t address);
    static const char* RegName(ZydisRegister reg);
    static const char* FlagsCondition(ZydisMnemonic mnemonic);
};
