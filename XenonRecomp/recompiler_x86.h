#pragma once

#include "pch.h"
#include "recompiler_config_x86.h"
#include <disasm_x86.h>

struct X86RecompilerLocalVariables
{
    bool eax{};
    bool ecx{};
    bool edx{};
    bool ebx{};
    bool esp{};
    bool ebp{};
    bool esi{};
    bool edi{};
    bool eflags{};
    bool fpu{};
    bool xmm[8]{};
    bool temp{};
    bool temp64{};
};

// Basic block for control flow analysis
struct X86BasicBlock
{
    uint32_t start = 0;         // Start address
    uint32_t end = 0;           // End address (exclusive)
    bool endsWithRet = false;   // Block ends with ret
    bool endsWithJmp = false;   // Block ends with unconditional jump
    bool fallsThrough = false;  // Block falls through to next
    uint32_t jumpTarget = 0;    // Target of unconditional jump (if any)
    std::vector<uint32_t> condTargets;  // Conditional branch targets
};

struct X86Recompiler
{
    Image image;
    std::vector<Function> functions;
    std::set<uint32_t> functionEntryPoints;  // All function entry addresses for tail call detection
    std::string out;
    size_t cppFileIndex = 0;
    X86RecompilerConfig config;

    bool LoadConfig(const std::string_view& configFilePath);

    template<class... Args>
    void print(fmt::format_string<Args...> fmt, Args&&... args)
    {
        fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    }

    template<class... Args>
    void println(fmt::format_string<Args...> fmt, Args&&... args)
    {
        fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
        out += '\n';
    }

    void println()
    {
        out += '\n';
    }

    void Analyse();

    // Result of control flow analysis
    struct ControlFlowResult {
        std::vector<X86BasicBlock> blocks;
        uint32_t effectiveBase;  // May be earlier than fn.base due to backward jumps
        uint32_t effectiveEnd;   // May be later than fn.base + fn.size
        bool hasChunks;          // True if function has discontinuous chunks
        std::set<std::pair<uint32_t, uint32_t>> functionRanges;  // All {start, end} ranges including chunks
    };

    // Recompile a single instruction
    bool RecompileInstruction(
        const Function& fn,
        uint32_t address,
        const x86::Insn& insn,
        const uint8_t* data,
        std::unordered_map<uint32_t, X86RecompilerSwitchTable>::iterator& switchTable,
        X86RecompilerLocalVariables& localVariables,
        bool needsFallThroughLabel,
        uint32_t effectiveBase,
        uint32_t effectiveEnd);

    // Analyze control flow and build basic blocks
    ControlFlowResult AnalyzeControlFlow(const Function& fn, const Section* section);
    
    // Collect all addresses that need labels
    std::set<uint32_t> CollectLabelAddresses(const Function& fn, const Section* section,
                                              const std::vector<X86BasicBlock>& blocks,
                                              uint32_t effectiveBase, uint32_t effectiveEnd);

    // Recompile an entire function
    bool Recompile(const Function& fn);

    // Recompile all functions and generate output files
    void Recompile(const std::filesystem::path& headerFilePath);

    void SaveCurrentOutData(const std::string_view& name = std::string_view());

    // Helper to get register name for code generation
    static const char* GetRegName32(x86::Reg reg);
    static const char* GetRegName16(x86::Reg reg);
    static const char* GetRegName8Lo(x86::Reg reg);
    static const char* GetRegName8Hi(x86::Reg reg);
    static const char* GetXmmRegName(x86::Reg reg);
    static const char* GetMmxRegName(x86::Reg reg);

    // Generate operand access code
    std::string FormatOperand(const x86::Operand& op, int size, X86RecompilerLocalVariables& locals);
    std::string FormatOperandRead(const x86::Operand& op, int size, X86RecompilerLocalVariables& locals);
    std::string FormatOperandWrite(const x86::Operand& op, const std::string& value, int size, X86RecompilerLocalVariables& locals);
    std::string FormatMemoryAddress(const x86::Operand& op, X86RecompilerLocalVariables& locals);
    
    // XMM operand formatting
    std::string FormatXmmOperandRead(const x86::Operand& op, X86RecompilerLocalVariables& locals);
    std::string FormatXmmOperandWrite(const x86::Operand& op, const std::string& value, X86RecompilerLocalVariables& locals);
};
