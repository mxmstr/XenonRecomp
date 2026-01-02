#pragma once

#include <string>
#include <vector>
#include <unordered_map>

// Switch table for x86 indirect jumps
struct X86RecompilerSwitchTable
{
    uint32_t reg;                   // Register containing the index
    uint32_t defaultLabel;          // Default case address (0 if none)
    std::vector<uint32_t> labels;   // Jump targets for each case
};

// Mid-asm hook for x86 code
struct X86RecompilerMidAsmHook
{
    std::string name;
    std::vector<std::string> registers;  // Registers to pass to hook function

    bool ret = false;               // Unconditionally return after hook
    bool returnOnTrue = false;      // Return if hook returns true
    bool returnOnFalse = false;     // Return if hook returns false

    uint32_t jumpAddress = 0;           // Unconditional jump after hook
    uint32_t jumpAddressOnTrue = 0;     // Jump if hook returns true
    uint32_t jumpAddressOnFalse = 0;    // Jump if hook returns false

    bool afterInstruction = false;  // Insert hook after instruction at address
};

// Address range within a section
struct X86RecompilerAddressRange
{
    uint32_t start;             // Start address (inclusive)
    uint32_t end;               // End address (exclusive)
};

// Section configuration - defines code and data regions within a section
struct X86RecompilerSectionConfig
{
    std::string name;                               // Section name (e.g., "XMV", "WMADEC")
    std::vector<X86RecompilerAddressRange> codeRanges;  // Code regions in this section
    std::vector<X86RecompilerAddressRange> dataRanges;  // Data regions in this section
    
    // Legacy support: single code_end_address (converted to code range)
    uint32_t codeEndAddress = 0;    // Address where code ends (data begins) - deprecated
};

struct X86RecompilerConfig
{
    // Paths
    std::string directoryPath;
    std::string filePath;               // Input XBE file
    std::string outDirectoryPath;       // Output directory for generated code
    std::string switchTableFilePath;    // Separate TOML for switch tables

    // Optimization flags
    bool eaxAsLocal = false;        // Treat EAX as local variable
    bool ecxAsLocal = false;        // Treat ECX as local variable  
    bool edxAsLocal = false;        // Treat EDX as local variable
    bool ebxAsLocal = false;        // Treat EBX as local variable (callee-saved)
    bool esiAsLocal = false;        // Treat ESI as local variable (callee-saved)
    bool ediAsLocal = false;        // Treat EDI as local variable (callee-saved)
    bool eflagsAsLocal = false;     // Treat EFLAGS as local variable
    bool fpuAsLocal = false;        // Treat FPU state as local variable

    // Special function addresses (CRT helpers)
    uint32_t longJmpAddress = 0;
    uint32_t setJmpAddress = 0;
    uint32_t allocaProbeAddress = 0;    // __alloca_probe / _chkstk
    uint32_t sehPrologAddress = 0;      // SEH prolog helper
    uint32_t sehEpilogAddress = 0;      // SEH epilog helper

    // Manual function definitions
    std::unordered_map<uint32_t, uint32_t> functions;  // address -> size

    // Function chunks - discontinuous code belonging to a function
    // Maps parent function address -> vector of {chunk_address, chunk_size}
    std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, uint32_t>>> functionChunks;

    // Single function recompilation (0 = recompile all)
    uint32_t singleFunctionAddress = 0;

    // Invalid instruction patterns to skip (padding, exception data)
    std::unordered_map<uint32_t, uint32_t> invalidInstructions;  // data pattern -> size
    std::unordered_map<uint32_t, uint32_t> invalidAddresses;     // specific address -> size

    // Switch tables
    std::unordered_map<uint32_t, X86RecompilerSwitchTable> switchTables;  // base address -> table

    // Mid-asm hooks
    std::unordered_map<uint32_t, X86RecompilerMidAsmHook> midAsmHooks;  // address -> hook

    // Section configurations - for mixed code/data sections with multiple regions
    std::unordered_map<std::string, X86RecompilerSectionConfig> sectionConfigs;  // section name -> config

    void Load(const std::string_view& configFilePath);
};
