#include "function_x86.h"
#include <disasm_x86.h>
#include <algorithm>
#include <set>

Function AnalyzeX86Function(const void* code, size_t maxSize, uint32_t base)
{
    Function fn{ base, 0 };
    
    const uint8_t* data = static_cast<const uint8_t*>(code);
    const uint8_t* dataEnd = data + maxSize;
    
    std::set<uint32_t> visited;
    std::vector<uint32_t> pending;
    pending.push_back(base);
    
    uint32_t maxAddr = base;
    
    while (!pending.empty())
    {
        uint32_t addr = pending.back();
        pending.pop_back();
        
        if (visited.count(addr) || addr < base || addr >= base + maxSize)
            continue;
            
        const uint8_t* p = data + (addr - base);
        
        while (p < dataEnd)
        {
            uint32_t curAddr = base + static_cast<uint32_t>(p - data);
            
            if (visited.count(curAddr))
                break;
                
            visited.insert(curAddr);
            
            x86::Insn insn;
            int len = x86::Disassemble(p, dataEnd - p, curAddr, insn);
            
            if (len <= 0 || insn.type == x86::InsnType::Invalid)
            {
                break;
            }
            
            // INT3 can be padding between functions or within a function
            // Only stop if we see multiple INT3s in a row
            if (insn.type == x86::InsnType::Int3)
            {
                // Check if next byte is also INT3 (padding)
                if (p + 1 < dataEnd && *(p + 1) == 0xCC)
                {
                    break; // Padding between functions
                }
                // Single INT3 might be intentional (debug break), continue
                p += len;
                maxAddr = std::max(maxAddr, curAddr + len);
                continue;
            }
            
            maxAddr = std::max(maxAddr, curAddr + len);
            
            // Handle branches
            if (insn.type == x86::InsnType::Jcc)
            {
                // Conditional branch - follow both paths
                if (insn.branch_target >= base && insn.branch_target < base + maxSize)
                {
                    pending.push_back(insn.branch_target);
                }
                // Continue to next instruction (fall-through)
                p += len;
            }
            else if (insn.type == x86::InsnType::Jmp)
            {
                // Unconditional jump
                if (insn.is_branch_relative && 
                    insn.branch_target >= base && 
                    insn.branch_target < base + maxSize)
                {
                    pending.push_back(insn.branch_target);
                }
                break; // End of this path
            }
            else if (insn.type == x86::InsnType::JmpIndirect)
            {
                // Jump table or tail call - can't follow statically
                break;
            }
            else if (insn.type == x86::InsnType::Ret)
            {
                // End of THIS path, but not necessarily the function
                // Other pending paths may extend further
                break;
            }
            else if (insn.type == x86::InsnType::Call)
            {
                // If next byte is INT3/padding, this is likely a noreturn call
                const uint8_t* next = p + len;
                if (next < dataEnd && *next == 0xCC)
                {
                    maxAddr = std::max(maxAddr, curAddr + len);
                    break; // Noreturn call, end of this path
                }
                // Call continues to next instruction
                p += len;
            }
            else
            {
                p += len;
            }
        }
    }
    
    fn.size = maxAddr - base;
    
    // Build basic blocks from visited addresses
    if (!visited.empty())
    {
        std::vector<uint32_t> sortedAddrs(visited.begin(), visited.end());
        std::sort(sortedAddrs.begin(), sortedAddrs.end());
        
        // For simplicity, treat the whole function as one block
        fn.blocks.emplace_back(0, fn.size);
    }
    
    return fn;
}

// Check if address looks like a valid function start
// Must be preceded by a function boundary (ret, int3, nop padding, or section start)
static bool IsPotentialFunctionStart(const uint8_t* p, const uint8_t* dataEnd, const uint8_t* dataStart)
{
    if (p >= dataEnd - 3) return false;
    
    // First check: must be after a function boundary (unless at section start)
    bool afterBoundary = (p == dataStart);
    if (!afterBoundary && p > dataStart)
    {
        uint8_t prev = *(p - 1);
        // ret (C3), int3 (CC), nop (90)
        // Note: We do NOT treat single 0x00 as padding - it could be part of an instruction
        // like "push 0" (6A 00) or "add [eax], al" (00 00)
        if (prev == 0xC3 || prev == 0xCC || prev == 0x90)
        {
            afterBoundary = true;
        }
        // Check for multiple consecutive int3/nop/null bytes (padding)
        if (!afterBoundary && p >= dataStart + 2)
        {
            uint8_t prev2 = *(p - 2);
            // At least 2 consecutive padding bytes suggests real padding
            if ((prev == 0x00 && prev2 == 0x00) ||
                (prev == 0xCC && prev2 == 0xCC) ||
                (prev == 0x90 && prev2 == 0x90) ||
                (prev == 0x00 && prev2 == 0xCC) ||
                (prev == 0xCC && prev2 == 0x00))
            {
                afterBoundary = true;
            }
        }
        // Check for retn imm16 (C2 xx xx) - need to look back further
        if (!afterBoundary && p >= dataStart + 3)
        {
            if (*(p - 3) == 0xC2)
            {
                afterBoundary = true;
            }
        }
    }
    
    if (!afterBoundary)
        return false;
    
    // Standard prologue: push ebp; mov ebp, esp
    // 55 8B EC = push ebp; mov ebp, esp
    // 55 89 E5 = push ebp; mov ebp, esp (alternate encoding)
    if (p[0] == 0x55)
    {
        // Must be EXACTLY mov ebp, esp (not mov ebp, [esp+disp])
        // 8B EC = mov ebp, esp (ModR/M: 11 101 100 = reg-reg, ebp <- esp)
        // 89 E5 = mov ebp, esp (ModR/M: 11 100 101 = reg-reg, esp -> ebp)
        if (p + 2 < dataEnd)
        {
            if ((p[1] == 0x8B && p[2] == 0xEC) ||  // mov ebp, esp
                (p[1] == 0x89 && p[2] == 0xE5))    // mov ebp, esp
            {
                return true;
            }
        }
        
        // push ebp followed by immediate mov ebp, esp with prefix (rare)
        // Or push ebp; push esi; push edi pattern (callee-save without frame)
        // Only trust this at clear boundaries
        if (p[1] >= 0x50 && p[1] <= 0x57)  // Another push
        {
            return true;
        }
        
        // push ebp; sub esp, imm (frame setup variant)
        if ((p[1] == 0x83 && p + 3 < dataEnd && p[2] == 0xEC) ||
            (p[1] == 0x81 && p + 6 < dataEnd && p[2] == 0xEC))
        {
            return true;
        }
    }
    
    // Naked function: sub esp, imm (allocating stack space first)
    // 83 EC xx = sub esp, imm8
    // 81 EC xx xx xx xx = sub esp, imm32
    if ((p[0] == 0x83 && p[1] == 0xEC) ||
        (p[0] == 0x81 && p[1] == 0xEC))
    {
        return true;
    }
    
    // push esi/edi/ebx at boundary (callee-save without frame pointer)
    // 53 = push ebx, 56 = push esi, 57 = push edi
    // Be more conservative here - only accept if after a STRONG boundary (ret or padding)
    if (p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57)
    {
        // Only trust this if clearly after ret (C3) or padding (CC, 90)
        if (p > dataStart)
        {
            uint8_t prev = *(p - 1);
            if (prev == 0xC3 || prev == 0xCC || prev == 0x90)
            {
                return true;
            }
            // Also accept after ret imm16
            if (p >= dataStart + 3 && *(p - 3) == 0xC2)
            {
                return true;
            }
        }
        return false;  // Don't trust single push reg after arbitrary byte
    }
    
    // mov edi, edi (hot-patching prologue used by Microsoft compilers)
    // 8B FF = mov edi, edi
    // This can also appear mid-function as alignment padding, so require strong boundary
    if (p[0] == 0x8B && p[1] == 0xFF)
    {
        if (p > dataStart)
        {
            uint8_t prev = *(p - 1);
            if (prev == 0xC3 || prev == 0xCC || prev == 0x90)
            {
                return true;
            }
            // Also accept after ret imm16
            if (p >= dataStart + 3 && *(p - 3) == 0xC2)
            {
                return true;
            }
        }
        return false;  // Don't trust mov edi,edi after arbitrary byte
    }
    
    return false;
}

std::vector<uint32_t> FindX86Functions(const void* code, size_t size, uint32_t base)
{
    std::vector<uint32_t> functions;
    const uint8_t* data = static_cast<const uint8_t*>(code);
    const uint8_t* dataEnd = data + size;
    
    std::set<uint32_t> foundFunctions;
    std::set<uint32_t> callTargets;
    
    // Linear scan to find all CALL instructions
    // Smart skip: only skip known padding bytes, jump to next alignment on failure
    const uint8_t* p = data;
    uint32_t addr = base;
    
    while (p < dataEnd)
    {
        x86::Insn insn;
        int len = x86::Disassemble(p, dataEnd - p, addr, insn);
        
        if (len <= 0 || insn.type == x86::InsnType::Invalid)
        {
            // Skip only single bytes that look like padding (00, CC, 90)
            if (*p == 0x00 || *p == 0xCC || *p == 0x90)
            {
                p++;
                addr++;
                continue;
            }
            // Unrecognized instruction - skip to next 16-byte aligned boundary
            uint32_t nextAlign = (addr + 16) & ~15;
            uint32_t skip = nextAlign - addr;
            if (skip > (uint32_t)(dataEnd - p))
                break;
            p += skip;
            addr = nextAlign;
            continue;
        }
        
        if (insn.type == x86::InsnType::Call && insn.is_branch_relative)
        {
            // Direct call - target is a function
            if (insn.branch_target >= base && insn.branch_target < base + size)
            {
                callTargets.insert(insn.branch_target);
            }
        }
        
        p += len;
        addr += len;
    }
    
    // Add section start as potential function (entry point often here)
    foundFunctions.insert(base);
    
    // Add all call targets as functions
    for (uint32_t target : callTargets)
    {
        foundFunctions.insert(target);
    }
    
    // NOTE: We intentionally do NOT scan for prologue patterns.
    // Functions that are only called indirectly (vtables, function pointers)
    // will need to be manually added to the TOML config file.
    
    // Convert to sorted vector
    functions.assign(foundFunctions.begin(), foundFunctions.end());
    std::sort(functions.begin(), functions.end());
    
    return functions;
}

// Scan backwards from jmp instruction to find cmp instruction
static bool FindSwitchBounds(const uint8_t* code, uint32_t jmpAddr, uint32_t base,
                             uint32_t& cmpAddr, uint32_t& caseCount, uint8_t& indexReg,
                             uint32_t& defaultLabel)
{
    // Scan backwards looking for pattern:
    // cmp reg, imm     ; compare index to max case
    // ja/jbe default   ; jump if out of bounds
    // ... (possibly mov reg to another reg)
    // jmp [table + reg*4]
    
    const uint8_t* p = code;
    int maxBacktrack = 64; // Don't look too far back
    
    for (int i = 0; i < maxBacktrack && p > code - (jmpAddr - base); i++)
    {
        p--;
        uint32_t addr = jmpAddr - i - 1;
        
        x86::Insn insn;
        int len = x86::Disassemble(p, 16, addr, insn);
        
        if (len <= 0) continue;
        
        // Look for JA (jump if above - unsigned greater) to default case
        if (insn.type == x86::InsnType::Jcc)
        {
            // JA (0x77 / 0x0F 87) or JBE (0x76 / 0x0F 86)
            if (insn.cond == x86::Condition::A || insn.cond == x86::Condition::BE)
            {
                defaultLabel = insn.branch_target;
                
                // Now find the CMP just before this
                const uint8_t* q = p;
                for (int j = 0; j < 16 && q > code - (jmpAddr - base); j++)
                {
                    q--;
                    x86::Insn cmpInsn;
                    int cmpLen = x86::Disassemble(q, 16, addr - j - 1, cmpInsn);
                    
                    if (cmpLen > 0 && cmpInsn.type == x86::InsnType::Cmp)
                    {
                        if (cmpInsn.op[0].type == x86::OpType::Reg &&
                            cmpInsn.op[1].type == x86::OpType::Imm)
                        {
                            cmpAddr = addr - j - 1;
                            caseCount = cmpInsn.op[1].imm + 1; // case count is max + 1
                            indexReg = cmpInsn.op[0].reg;
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    return false;
}

std::vector<X86SwitchTable> FindX86JumpTables(const void* code, size_t size, uint32_t base,
                                               const uint8_t* imageBase, uint32_t imageStart)
{
    std::vector<X86SwitchTable> tables;
    const uint8_t* data = static_cast<const uint8_t*>(code);
    const uint8_t* dataEnd = data + size;
    
    for (const uint8_t* p = data; p < dataEnd - 6; p++)
    {
        uint32_t addr = base + static_cast<uint32_t>(p - data);
        
        x86::Insn insn;
        int len = x86::Disassemble(p, dataEnd - p, addr, insn);
        
        if (len <= 0) continue;
        
        // Look for indirect jump patterns:
        // FF 24 85 xx xx xx xx  - jmp [reg*4 + disp32] - jump table
        // FF 24 8D xx xx xx xx  - jmp [reg*4 + disp32] - (different reg encoding)
        // FF 24 95 xx xx xx xx  - jmp [edx*4 + disp32]
        // etc.
        
        if (insn.type == x86::InsnType::JmpIndirect)
        {
            // Check for scaled index addressing [base + index*4 + disp]
            // or just [index*4 + disp]
            if (insn.op[0].type == x86::OpType::Mem || insn.op[0].type == x86::OpType::MemDisp)
            {
                const auto& op = insn.op[0];
                
                // Jump table pattern: scale should be 4 (dword table)
                // and should have displacement (table address)
                if (op.scale == 4 && op.index != x86::X86_REG_NONE)
                {
                    X86SwitchTable table;
                    table.address = addr;
                    table.indexReg = op.index;
                    table.scale = op.scale;
                    table.type = X86_SWITCH_DIRECT;
                    
                    // Calculate table address
                    // If there's a base register, this is more complex
                    if (op.base == x86::X86_REG_NONE)
                    {
                        table.tableAddress = static_cast<uint32_t>(op.disp);
                    }
                    else
                    {
                        // Base + index*4 + disp - need to figure out base value
                        // This is harder without runtime info
                        // For now, just use displacement as hint
                        table.tableAddress = static_cast<uint32_t>(op.disp);
                    }
                    
                    // Try to find the bounds check (cmp + ja/jbe)
                    table.caseCount = 0;
                    table.defaultLabel = 0;
                    table.cmpAddress = 0;
                    
                    if (FindSwitchBounds(p, addr, base, 
                                        table.cmpAddress, table.caseCount, 
                                        table.indexReg, table.defaultLabel))
                    {
                        // Found a valid switch table
                        if (table.caseCount > 0 && table.caseCount < 1024) // sanity check
                        {
                            // Read the table entries
                            ReadX86JumpTable(table, imageBase, imageStart);
                            
                            if (!table.labels.empty())
                            {
                                tables.push_back(std::move(table));
                            }
                        }
                    }
                }
            }
        }
        
        // Don't skip by instruction length - we might miss overlapping patterns
        // Move by 1 byte to catch all possible alignments
    }
    
    return tables;
}

void ReadX86JumpTable(X86SwitchTable& table, const uint8_t* imageBase, uint32_t imageStart)
{
    if (table.tableAddress == 0 || table.caseCount == 0)
        return;
        
    // Calculate offset into image
    if (table.tableAddress < imageStart)
        return;
        
    size_t offset = table.tableAddress - imageStart;
    const uint32_t* entries = reinterpret_cast<const uint32_t*>(imageBase + offset);
    
    table.labels.reserve(table.caseCount);
    
    // Code section typically starts near the beginning and is limited in size
    // A valid jump table entry should be:
    // 1. Within a reasonable range of the jump instruction (within ~1MB)
    // 2. Not obviously byte data misinterpreted as address
    uint32_t minValid = imageStart;
    uint32_t maxValid = imageStart + 0x400000; // 4MB max - reasonable for code section
    
    for (uint32_t i = 0; i < table.caseCount; i++)
    {
        // x86 is little-endian, so no byte swap needed
        uint32_t target = entries[i];
        
        // Stricter sanity checks:
        // 1. Target should be in valid code range
        // 2. Target should be reasonably close to the table (within ~1MB)
        // 3. Target should look like a code address (not small consecutive bytes)
        bool isValid = (target >= minValid && target < maxValid);
        
        // Also reject addresses that look like byte patterns (e.g., 0x03020100)
        // Real code addresses are unlikely to have such regular low-byte patterns
        if (isValid)
        {
            uint8_t b0 = (target >> 0) & 0xFF;
            uint8_t b1 = (target >> 8) & 0xFF;
            uint8_t b2 = (target >> 16) & 0xFF;
            uint8_t b3 = (target >> 24) & 0xFF;
            
            // Check for consecutive small bytes (index table data)
            if (b3 < 0x10 && b2 < 0x20 && b1 < 0x20 && b0 < 0x20)
            {
                // Looks like data, not a code address
                // Real addresses in XBE start around 0x10000+
                isValid = false;
            }
        }
        
        if (isValid)
        {
            table.labels.push_back(target);
        }
        else
        {
            // Invalid entry - table might be corrupted or misidentified
            // Stop reading
            break;
        }
    }
}
