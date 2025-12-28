#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include "function.h"

// Forward declaration
namespace x86 { struct Insn; }

// x86 jump table types
enum X86SwitchType
{
    X86_SWITCH_DIRECT,      // jmp [table + reg*4]
    X86_SWITCH_SCALED,      // jmp [base + reg*scale + disp]
};

struct X86SwitchTable
{
    uint32_t address;           // Address of the jmp instruction
    uint32_t tableAddress;      // Address of the jump table data
    uint32_t cmpAddress;        // Address of the cmp instruction (for case count)
    uint32_t defaultLabel;      // Default case target (for ja/jbe before switch)
    uint32_t caseCount;         // Number of cases
    uint8_t indexReg;           // Register used as index
    uint8_t scale;              // Scale factor (usually 4)
    X86SwitchType type;
    std::vector<uint32_t> labels;  // Jump targets
};

// Analyze an x86 function to determine its size/blocks
// Similar to the PPC Function::Analyze but for x86 code
Function AnalyzeX86Function(const void* code, size_t maxSize, uint32_t base);

// Scan code section for function boundaries based on prologue patterns
// Returns vector of function start addresses
std::vector<uint32_t> FindX86Functions(const void* code, size_t size, uint32_t base);

// Scan for x86 jump tables (switch statements)
// Returns detected switch tables
std::vector<X86SwitchTable> FindX86JumpTables(const void* code, size_t size, uint32_t base,
                                               const uint8_t* imageBase, uint32_t imageStart);

// Read jump table entries from memory
void ReadX86JumpTable(X86SwitchTable& table, const uint8_t* imageBase, uint32_t imageStart);
