#include "pch.h"
#include "recompiler_x86.h"
#include "recompiler_config_x86.h"
#include <xbe.h>

const char* X86Recompiler::GetRegName32(x86::Reg reg)
{
    static const char* names[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
    return reg < 8 ? names[reg] : "???";
}

const char* X86Recompiler::GetRegName16(x86::Reg reg)
{
    static const char* names[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
    return reg < 8 ? names[reg] : "???";
}

const char* X86Recompiler::GetRegName8Lo(x86::Reg reg)
{
    static const char* names[] = { "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil" };
    return reg < 8 ? names[reg] : "???";
}

const char* X86Recompiler::GetRegName8Hi(x86::Reg reg)
{
    static const char* names[] = { "ah", "ch", "dh", "bh", "???", "???", "???", "???" };
    return reg < 4 ? names[reg] : "???";
}

const char* X86Recompiler::GetXmmRegName(x86::Reg reg)
{
    static const char* names[] = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" };
    return reg < 8 ? names[reg] : "???";
}

const char* X86Recompiler::GetMmxRegName(x86::Reg reg)
{
    static const char* names[] = { "mm[0]", "mm[1]", "mm[2]", "mm[3]", "mm[4]", "mm[5]", "mm[6]", "mm[7]" };
    return reg < 8 ? names[reg] : "???";
}

bool X86Recompiler::LoadConfig(const std::string_view& configFilePath)
{
    config.Load(configFilePath);

    std::vector<uint8_t> file = LoadFile((config.filePath).c_str());
    if (file.empty())
    {
        fmt::println("ERROR: Unable to load the XBE file");
        return false;
    }

    image = Image::ParseImage(file.data(), file.size());
    return true;
}

void X86Recompiler::Analyse()
{
    // Add manually specified functions from config
    for (auto& [address, size] : config.functions)
    {
        functions.emplace_back(address, size);
        image.symbols.emplace(fmt::format("sub_{:X}", address), address, size, Symbol_Function);
    }
    
    if (!config.functions.empty())
    {
        fmt::println("Loaded {} manually-specified functions from TOML:", config.functions.size());
        // for (auto& [address, size] : config.functions)
        // {
        //     fmt::println("  0x{:X} (size: 0x{:X})", address, size);
        // }
    }

    // Helper to check if an address falls within a manually-specified function
    auto isInManualFunction = [&](uint32_t addr) -> bool {
        for (const auto& [fnAddr, fnSize] : config.functions)
        {
            if (addr >= fnAddr && addr < fnAddr + fnSize)
                return true;
        }
        return false;
    };

    // Helper to check if an address is close to a manually-specified function start
    // (within 16 bytes - likely a misdetection of the same function)
    auto isNearManualFunction = [&](uint32_t addr) -> bool {
        for (const auto& [fnAddr, fnSize] : config.functions)
        {
            // Check if addr is within 16 bytes before or after the manual function start
            if (addr >= fnAddr - 16 && addr < fnAddr + 16)
                return true;
        }
        return false;
    };

    // Build a map of section data for quick lookup
    struct SectionInfo {
        const uint8_t* data;
        uint32_t base;
        uint32_t size;
        std::string name;
    };
    std::vector<SectionInfo> codeSections;  // Code sections with boundary-limited sizes (for finding code)
    std::vector<SectionInfo> allSections;   // All sections with full sizes (for reading data like jump tables)
    
    // Helper to check if an address is in a data range
    auto isInDataRange = [&](uint32_t addr, const std::string& sectionName) -> bool {
        auto configIt = config.sectionConfigs.find(sectionName);
        if (configIt != config.sectionConfigs.end()) {
            for (const auto& range : configIt->second.dataRanges) {
                if (addr >= range.start && addr < range.end)
                    return true;
            }
        }
        return false;
    };
    
    for (const auto& section : image.sections)
    {
        // Add to allSections with full size
        allSections.push_back({section.data, static_cast<uint32_t>(section.base), 
                               static_cast<uint32_t>(section.size), section.name});
        
        if (section.flags & SectionFlags_Code)
        {
            uint32_t sectionBase = static_cast<uint32_t>(section.base);
            uint32_t sectionEnd = sectionBase + static_cast<uint32_t>(section.size);
            
            // Check if there's a section config defined for this section
            auto configIt = config.sectionConfigs.find(section.name);
            if (configIt != config.sectionConfigs.end())
            {
                const auto& sectionConfig = configIt->second;
                
                // New format: explicit code_ranges
                if (!sectionConfig.codeRanges.empty())
                {
                    fmt::println("  Code section '{}' with {} code range(s):", 
                                 section.name, sectionConfig.codeRanges.size());
                    for (const auto& range : sectionConfig.codeRanges)
                    {
                        uint32_t rangeStart = range.start;
                        uint32_t rangeEnd = range.end;
                        
                        // Clamp to section bounds
                        if (rangeStart < sectionBase) rangeStart = sectionBase;
                        if (rangeEnd > sectionEnd) rangeEnd = sectionEnd;
                        
                        if (rangeStart < rangeEnd)
                        {
                            uint32_t offset = rangeStart - sectionBase;
                            uint32_t size = rangeEnd - rangeStart;
                            codeSections.push_back({section.data + offset, rangeStart, size, section.name});
                            fmt::println("    Code range: 0x{:X} - 0x{:X}", rangeStart, rangeEnd);
                        }
                    }
                    if (!sectionConfig.dataRanges.empty())
                    {
                        fmt::println("    {} data range(s) defined", sectionConfig.dataRanges.size());
                    }
                }
                // Legacy format: single code_end_address
                else if (sectionConfig.codeEndAddress != 0)
                {
                    uint32_t codeEnd = sectionConfig.codeEndAddress;
                    if (codeEnd > sectionBase && codeEnd <= sectionEnd)
                    {
                        uint32_t codeSize = codeEnd - sectionBase;
                        fmt::println("  Code section '{}': 0x{:X} - 0x{:X} (manual boundary, data starts at 0x{:X})", 
                                     section.name, sectionBase, codeEnd, codeEnd);
                        codeSections.push_back({section.data, sectionBase, codeSize, section.name});
                    }
                    else
                    {
                        fmt::println("  WARNING: Invalid section boundary for '{}': 0x{:X} is outside section range",
                                     section.name, codeEnd);
                        fmt::println("  Code section '{}': 0x{:X} - 0x{:X}", section.name, sectionBase, sectionEnd);
                        codeSections.push_back({section.data, sectionBase, static_cast<uint32_t>(section.size), section.name});
                    }
                }
                else
                {
                    // Config exists but no code ranges or boundary - use full section
                    fmt::println("  Code section '{}': 0x{:X} - 0x{:X}", section.name, sectionBase, sectionEnd);
                    codeSections.push_back({section.data, sectionBase, static_cast<uint32_t>(section.size), section.name});
                }
            }
            else
            {
                fmt::println("  Code section '{}': 0x{:X} - 0x{:X}", section.name, sectionBase, sectionEnd);
                codeSections.push_back({section.data, sectionBase, static_cast<uint32_t>(section.size), section.name});
            }
        }
    }

    auto getSectionForAddr = [&](uint32_t addr) -> const SectionInfo* {
        for (const auto& sec : codeSections)
        {
            if (addr >= sec.base && addr < sec.base + sec.size)
                return &sec;
        }
        return nullptr;
    };
    
    // Get any section (including data sections) for reading jump tables etc.
    auto getAnySectionForAddr = [&](uint32_t addr) -> const SectionInfo* {
        for (const auto& sec : allSections)
        {
            if (addr >= sec.base && addr < sec.base + sec.size)
                return &sec;
        }
        return nullptr;
    };

    // Phase 1: Recursive descent from entry point to find valid instruction addresses
    std::set<uint32_t> validInsnAddrs;  // All addresses that are valid instruction starts
    std::set<uint32_t> callTargets;     // CALL targets found during descent
    std::vector<uint32_t> workList;

    // Seed with entry point
    if (image.entry_point != 0)
    {
        workList.push_back(static_cast<uint32_t>(image.entry_point));
        callTargets.insert(static_cast<uint32_t>(image.entry_point));
    }

    // Process all reachable code
    while (!workList.empty())
    {
        uint32_t startAddr = workList.back();
        workList.pop_back();

        if (validInsnAddrs.count(startAddr))
            continue;

        const SectionInfo* sec = getSectionForAddr(startAddr);
        if (!sec)
            continue;

        const uint8_t* p = sec->data + (startAddr - sec->base);
        const uint8_t* pEnd = sec->data + sec->size;
        uint32_t addr = startAddr;

        while (p < pEnd)
        {
            if (validInsnAddrs.count(addr))
                break;  // Already processed from another path
            validInsnAddrs.insert(addr);

            x86::Insn insn;
            int len = x86::Disassemble(p, pEnd - p, addr, insn);
            if (len <= 0 || insn.type == x86::InsnType::Invalid)
                break;

            // Track CALL targets
            if (insn.type == x86::InsnType::Call && insn.is_branch_relative)
            {
                auto targetSec = getSectionForAddr(insn.branch_target);
                if (targetSec && !callTargets.count(insn.branch_target))
                {
                    // Debug: trace calls to XPP section
                    if (insn.branch_target >= 0x362AE0 && insn.branch_target < 0x36B7B0)
                    {
                        fmt::println("DEBUG: Found CALL to XPP 0x{:X} from 0x{:X}", insn.branch_target, addr);
                    }
                    callTargets.insert(insn.branch_target);
                    workList.push_back(insn.branch_target);
                }
                else if (!targetSec && insn.branch_target >= 0x10000)
                {
                    fmt::println("DEBUG: CALL to 0x{:X} from 0x{:X} - target not in any code section!", insn.branch_target, addr);
                }
            }

            // Follow control flow
            if (insn.type == x86::InsnType::Jcc && insn.is_branch_relative)
            {
                // Queue branch target
                if (getSectionForAddr(insn.branch_target) && !validInsnAddrs.count(insn.branch_target))
                {
                    workList.push_back(insn.branch_target);
                }
                // Continue to fall-through
                p += len;
                addr += len;
            }
            else if (insn.type == x86::InsnType::Jmp && insn.is_branch_relative)
            {
                // Queue target and stop this path
                if (getSectionForAddr(insn.branch_target) && !validInsnAddrs.count(insn.branch_target))
                {
                    workList.push_back(insn.branch_target);
                }
                break;
            }
            else if (insn.type == x86::InsnType::Ret || 
                     insn.type == x86::InsnType::JmpIndirect ||
                     insn.type == x86::InsnType::Int3)
            {
                break;
            }
            else
            {
                p += len;
                addr += len;
            }
        }
    }

    fmt::println("Phase 1: Found {} valid instruction addresses, {} call targets from entry point",
                 validInsnAddrs.size(), callTargets.size());

    // Phase 2: Find additional function entry points by looking for:
    // 1. Common function prologues at aligned addresses
    // 2. Addresses after terminators (ret, jmp indirect, int3) at aligned boundaries
    std::set<uint32_t> additionalCallTargets;
    
    for (const auto& sec : codeSections)
    {
        const uint8_t* data = sec.data;
        uint32_t addr = sec.base;
        uint32_t endAddr = sec.base + sec.size;

        while (addr < endAddr - 4)
        {
            const uint8_t* p = data + (addr - sec.base);
            
            // Check for common function prologues at 16-byte aligned addresses
            // or addresses right after known terminators
            bool isPotentialEntry = false;
            
            // Check alignment (functions often start at 4 or 16 byte boundaries)
            if ((addr & 0xF) == 0 || (addr & 0x3) == 0)
            {
                // push ebp (0x55) followed by mov ebp, esp (0x8B EC or 0x89 E5)
                if (p[0] == 0x55 && ((p[1] == 0x8B && p[2] == 0xEC) || (p[1] == 0x89 && p[2] == 0xE5)))
                {
                    isPotentialEntry = true;
                }
                // push ebx/esi/edi (0x53/0x56/0x57) - common for __fastcall
                else if (p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57)
                {
                    // Check if followed by more pushes or sub esp
                    if (p[1] == 0x53 || p[1] == 0x56 || p[1] == 0x57 || p[1] == 0x55 ||
                        (p[1] == 0x83 && p[2] == 0xEC) || // sub esp, imm8
                        (p[1] == 0x81 && p[2] == 0xEC))   // sub esp, imm32
                    {
                        isPotentialEntry = true;
                    }
                }
                // sub esp, imm (stack frame setup)
                else if ((p[0] == 0x83 && p[1] == 0xEC) || (p[0] == 0x81 && p[1] == 0xEC))
                {
                    isPotentialEntry = true;
                }
                // mov edi, edi (hotpatch NOP)
                else if (p[0] == 0x8B && p[1] == 0xFF)
                {
                    isPotentialEntry = true;
                }
            }
            
            if (isPotentialEntry && !callTargets.count(addr) && !validInsnAddrs.count(addr) && !isInManualFunction(addr) && !isNearManualFunction(addr))
            {
                // Verify this isn't inside an instruction we already decoded
                bool insideKnownInsn = false;
                for (uint32_t check = addr - 1; check >= addr - 15 && check >= sec.base; check--)
                {
                    if (validInsnAddrs.count(check))
                    {
                        const uint8_t* checkP = data + (check - sec.base);
                        x86::Insn checkInsn;
                        int checkLen = x86::Disassemble(checkP, endAddr - check, check, checkInsn);
                        if (checkLen > 0 && check + checkLen > addr)
                        {
                            insideKnownInsn = true;
                        }
                        break;
                    }
                }
                
                if (!insideKnownInsn)
                {
                    additionalCallTargets.insert(addr);
                }
            }
            
            addr++;
        }
    }

    fmt::println("Phase 2a: Found {} potential function prologues",
                 additionalCallTargets.size());

    // Phase 2b: Scan data sections for function pointers (vtables, callbacks)
    // These are addresses in data sections that point to code sections
    size_t dataFuncPtrs = 0;
    for (const auto& section : image.sections)
    {
        // Skip code sections, look at data sections (especially .rdata)
        if (section.flags & SectionFlags_Code)
            continue;
        
        // Scan for dword-aligned values that look like code addresses
        const uint32_t* data = reinterpret_cast<const uint32_t*>(section.data);
        size_t count = section.size / 4;
        
        for (size_t i = 0; i < count; i++)
        {
            uint32_t value = data[i];
            
            // Check if this value points to a code section
            const SectionInfo* targetSec = getSectionForAddr(value);
            if (targetSec && !callTargets.count(value) && !additionalCallTargets.count(value) && !isInManualFunction(value) && !isNearManualFunction(value))
            {
                // Additional validation: try to disassemble at the target
                const uint8_t* p = targetSec->data + (value - targetSec->base);
                x86::Insn insn;
                int len = x86::Disassemble(p, targetSec->size - (value - targetSec->base), value, insn);
                
                if (len > 0 && insn.type != x86::InsnType::Invalid)
                {
                    // Looks like a valid function pointer
                    additionalCallTargets.insert(value);
                    dataFuncPtrs++;
                }
            }
        }
    }

    fmt::println("Phase 2b: Found {} potential function pointers in data sections",
                 dataFuncPtrs);

    // Phase 3: Do recursive descent from each potential entry point
    // This will find all CALL targets reachable from these functions too
    for (uint32_t target : additionalCallTargets)
    {
        // Skip if already known
        if (callTargets.count(target))
            continue;

        // Add and queue for processing
        callTargets.insert(target);
        workList.push_back(target);
    }

    // Process all new functions (recursive descent)
    while (!workList.empty())
    {
        uint32_t startAddr = workList.back();
        workList.pop_back();

        if (validInsnAddrs.count(startAddr))
            continue;

        const SectionInfo* sec = getSectionForAddr(startAddr);
        if (!sec)
            continue;

        const uint8_t* p = sec->data + (startAddr - sec->base);
        const uint8_t* pEnd = sec->data + sec->size;
        uint32_t addr = startAddr;

        while (p < pEnd)
        {
            if (validInsnAddrs.count(addr))
                break;
            validInsnAddrs.insert(addr);

            x86::Insn insn;
            int len = x86::Disassemble(p, pEnd - p, addr, insn);
            if (len <= 0 || insn.type == x86::InsnType::Invalid)
                break;

            if (insn.type == x86::InsnType::Call && insn.is_branch_relative)
            {
                if (getSectionForAddr(insn.branch_target) && !callTargets.count(insn.branch_target))
                {
                    callTargets.insert(insn.branch_target);
                    workList.push_back(insn.branch_target);
                }
            }

            if (insn.type == x86::InsnType::Jcc && insn.is_branch_relative)
            {
                if (getSectionForAddr(insn.branch_target) && !validInsnAddrs.count(insn.branch_target))
                {
                    workList.push_back(insn.branch_target);
                }
                p += len;
                addr += len;
            }
            else if (insn.type == x86::InsnType::Jmp && insn.is_branch_relative)
            {
                if (getSectionForAddr(insn.branch_target) && !validInsnAddrs.count(insn.branch_target))
                {
                    workList.push_back(insn.branch_target);
                }
                break;
            }
            else if (insn.type == x86::InsnType::Ret || 
                     insn.type == x86::InsnType::JmpIndirect ||
                     insn.type == x86::InsnType::Int3)
            {
                break;
            }
            else
            {
                p += len;
                addr += len;
            }
        }
    }

    fmt::println("Phase 3: Total {} call targets after validation", callTargets.size());

    // Add all validated call targets as functions, unless they're inside/near manually-specified functions
    for (uint32_t target : callTargets)
    {
        if (image.symbols.find(target) == image.symbols.end() && !isInManualFunction(target) && !isNearManualFunction(target))
        {
            auto& fn = functions.emplace_back();
            fn.base = target;
            fn.size = 0;
            image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
        }
    }

    // Sort functions by address
    std::sort(functions.begin(), functions.end(), 
              [](auto& a, auto& b) { return a.base < b.base; });

    // Remove duplicates
    functions.erase(std::unique(functions.begin(), functions.end(),
                   [](auto& a, auto& b) { return a.base == b.base; }), 
                   functions.end());

    // Calculate function sizes based on actual code flow, not next function
    // A function's size is determined by the furthest instruction reachable from it
    // We use SECTION boundary, not next function, because functions can overlap
    // or false functions may exist inside real functions
    for (size_t i = 0; i < functions.size(); i++)
    {
        if (functions[i].size != 0)
            continue;

        const SectionInfo* sec = getSectionForAddr(functions[i].base);
        if (!sec)
            continue;

        // Find max address reachable from this function
        std::set<uint32_t> funcAddrs;
        std::vector<uint32_t> funcWorkList;
        funcWorkList.push_back(functions[i].base);
        uint32_t maxAddr = functions[i].base;

        // Use SECTION boundary only - don't constrain by next function
        // This allows proper function size calculation even if there are
        // false functions detected in the middle
        uint32_t boundary = sec->base + sec->size;

        while (!funcWorkList.empty())
        {
            uint32_t addr = funcWorkList.back();
            funcWorkList.pop_back();

            if (funcAddrs.count(addr) || addr < functions[i].base || addr >= boundary)
                continue;
            funcAddrs.insert(addr);

            const uint8_t* p = sec->data + (addr - sec->base);
            const uint8_t* pEnd = sec->data + sec->size;

            x86::Insn insn;
            int len = x86::Disassemble(p, pEnd - p, addr, insn);
            if (len <= 0)
                continue;

            uint32_t endAddr = addr + len;
            if (endAddr > maxAddr)
                maxAddr = endAddr;

            if (insn.type == x86::InsnType::Jcc && insn.is_branch_relative)
            {
                if (insn.branch_target >= functions[i].base && insn.branch_target < boundary)
                    funcWorkList.push_back(insn.branch_target);
                funcWorkList.push_back(addr + len);
            }
            else if (insn.type == x86::InsnType::Jmp && insn.is_branch_relative)
            {
                if (insn.branch_target >= functions[i].base && insn.branch_target < boundary)
                    funcWorkList.push_back(insn.branch_target);
            }
            else if (insn.type != x86::InsnType::Ret && 
                     insn.type != x86::InsnType::JmpIndirect &&
                     insn.type != x86::InsnType::Int3)
            {
                funcWorkList.push_back(addr + len);
            }
        }

        functions[i].size = maxAddr - functions[i].base;
    }

    // Update symbols with computed sizes
    for (size_t i = 0; i < functions.size(); i++)
    {
        if (functions[i].size == 0)
        {
            // Find section for fallback calculation
            const SectionInfo* sec = getSectionForAddr(functions[i].base);
            if (sec)
            {
                // Use section end as fallback
                uint32_t endAddress = sec->base + sec->size;
                if (i + 1 < functions.size() && 
                    functions[i + 1].base > functions[i].base &&
                    functions[i + 1].base < endAddress)
                {
                    endAddress = functions[i + 1].base;
                }
                functions[i].size = endAddress - functions[i].base;
            }
        }

        // Update symbol
        auto it = image.symbols.find(functions[i].base);
        if (it != image.symbols.end())
        {
            Symbol updated = *it;
            updated.size = functions[i].size;
            image.symbols.erase(it);
            image.symbols.insert(updated);
        }
    }

    // Phase 4: Ensure all CALL targets from discovered functions are also functions
    // This catches any functions called by code we discovered that weren't found earlier
    std::set<uint32_t> missingFunctions;
    std::set<uint32_t> existingFunctions;
    for (const auto& fn : functions)
        existingFunctions.insert(fn.base);

    for (const auto& fn : functions)
    {
        const SectionInfo* sec = getSectionForAddr(fn.base);
        if (!sec)
            continue;

        const uint8_t* p = sec->data + (fn.base - sec->base);
        const uint8_t* pEnd = sec->data + sec->size;
        uint32_t addr = fn.base;
        uint32_t fnEnd = fn.base + fn.size;

        while (addr < fnEnd && p < pEnd)
        {
            x86::Insn insn;
            int len = x86::Disassemble(p, pEnd - p, addr, insn);
            if (len <= 0)
                break;

            if (insn.type == x86::InsnType::Call && insn.is_branch_relative)
            {
                uint32_t target = insn.branch_target;
                if (getSectionForAddr(target) && 
                    !existingFunctions.count(target) &&
                    !missingFunctions.count(target) &&
                    !isInManualFunction(target) &&
                    !isNearManualFunction(target))
                {
                    missingFunctions.insert(target);
                }
            }
            
            // Also check for JMP targets that go outside this function's boundaries
            // These are often "function chunks" - code that belongs to this function
            // but was placed elsewhere by the compiler
            if (insn.type == x86::InsnType::Jmp && insn.is_branch_relative)
            {
                uint32_t target = insn.branch_target;
                // If jump target is outside this function's bounds, it's a chunk
                if (target < fn.base || target >= fn.base + fn.size)
                {
                    if (getSectionForAddr(target) && 
                        !existingFunctions.count(target) &&
                        !missingFunctions.count(target) &&
                        !isInManualFunction(target) &&
                        !isNearManualFunction(target))
                    {
                        missingFunctions.insert(target);
                    }
                }
            }

            p += len;
            addr += len;
        }
    }

    // Add missing functions
    if (!missingFunctions.empty())
    {
        fmt::println("Phase 4: Found {} additional targets (calls + function chunks)", missingFunctions.size());
        
        for (uint32_t target : missingFunctions)
        {
            auto& fn = functions.emplace_back();
            fn.base = target;
            fn.size = 0;
            image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
        }

        // Re-sort and calculate sizes for new functions
        std::sort(functions.begin(), functions.end(), 
                  [](auto& a, auto& b) { return a.base < b.base; });

        for (size_t i = 0; i < functions.size(); i++)
        {
            if (functions[i].size != 0)
                continue;

            const SectionInfo* sec = getSectionForAddr(functions[i].base);
            if (!sec)
                continue;

            uint32_t endAddress = sec->base + sec->size;
            if (i + 1 < functions.size() && 
                functions[i + 1].base > functions[i].base &&
                functions[i + 1].base < endAddress)
            {
                endAddress = functions[i + 1].base;
            }
            functions[i].size = endAddress - functions[i].base;

            auto it = image.symbols.find(functions[i].base);
            if (it != image.symbols.end())
            {
                Symbol updated = *it;
                updated.size = functions[i].size;
                image.symbols.erase(it);
                image.symbols.insert(updated);
            }
        }
    }

    // Phase 5: Remove false positives - functions that are reachable from another function
    // This happens when prologue patterns like "push esi; push edi" appear mid-function
    // We check if the function's address is reachable via control flow from an earlier function
    // IMPORTANT: We mark ALL bytes within each instruction as "covered" to catch addresses
    // that fall in the middle of multi-byte instructions
    {
        std::map<uint32_t, uint32_t> addrToFunc;  // Maps address to function that covers it
        
        // Build a set of all function entry points - jumps to these are tail calls, not internal flow
        std::set<uint32_t> functionEntryPoints;
        for (const auto& fn : functions)
        {
            functionEntryPoints.insert(fn.base);
        }
        
        // First, calculate coverage for each function (all bytes within all reachable instructions)
        for (const auto& fn : functions)
        {
            const SectionInfo* sec = getSectionForAddr(fn.base);
            if (!sec) continue;
            
            std::vector<uint32_t> workList;
            std::set<uint32_t> visitedInsns;  // Track visited instruction starts
            workList.push_back(fn.base);
            
            while (!workList.empty())
            {
                uint32_t addr = workList.back();
                workList.pop_back();
                
                // Don't follow control flow into OTHER functions (tail calls)
                // But DO process our own entry point
                if (addr != fn.base && functionEntryPoints.count(addr))
                    continue;
                
                if (visitedInsns.count(addr) || addr < sec->base || addr >= sec->base + sec->size)
                    continue;
                visitedInsns.insert(addr);
                
                const uint8_t* p = sec->data + (addr - sec->base);
                x86::Insn insn;
                int len = x86::Disassemble(p, sec->size - (addr - sec->base), addr, insn);
                if (len <= 0) continue;
                
                // Mark ALL bytes within this instruction as covered by this function
                // This catches false functions that start mid-instruction
                for (int b = 0; b < len; b++)
                {
                    uint32_t byteAddr = addr + b;
                    if (byteAddr != fn.base && addrToFunc.find(byteAddr) == addrToFunc.end())
                    {
                        addrToFunc[byteAddr] = fn.base;
                    }
                }
                
                if (insn.type == x86::InsnType::Jcc && insn.is_branch_relative)
                {
                    workList.push_back(insn.branch_target);
                    workList.push_back(addr + len);
                }
                else if (insn.type == x86::InsnType::Jmp && insn.is_branch_relative)
                {
                    workList.push_back(insn.branch_target);
                }
                else if (insn.type == x86::InsnType::JmpIndirect)
                {
                    // JmpIndirect is ALWAYS a terminator - execution never falls through
                    // This handles both:
                    // 1. Switch tables (jmp dword ptr [reg*4 + tableAddr]) - targets added to worklist
                    // 2. Import jumps (jmp dword ptr [import_addr]) - no fallthrough to next insn
                    
                    // Try to detect and read switch table for reachability
                    // Pattern: jmp dword ptr [reg*4 + tableAddr]
                    const auto& op = insn.op[0];
                    if (op.type == x86::OpType::Mem && op.scale == 4 && op.base == x86::X86_REG_NONE)
                    {
                        uint32_t tableAddr = static_cast<uint32_t>(op.disp);
                        // Use getAnySectionForAddr since jump table data may be outside code boundaries
                        const SectionInfo* tableSec = getAnySectionForAddr(tableAddr);
                        
                        if (tableSec)
                        {
                            const uint8_t* tableData = tableSec->data + (tableAddr - tableSec->base);
                            size_t maxEntries = (tableSec->size - (tableAddr - tableSec->base)) / 4;
                            if (maxEntries > 256) maxEntries = 256;
                            
                            // Debug: print first few entries of the table
                            //fmt::println("  Switch table at 0x{:X} (insn at 0x{:X}), section '{}' base=0x{:X}:", 
                            //             tableAddr, addr, tableSec->name, tableSec->base);
                            for (size_t dbg = 0; dbg < (std::min)(size_t(5), maxEntries); dbg++)
                            {
                                uint32_t dbgTarget = *reinterpret_cast<const uint32_t*>(tableData + dbg * 4);
                                //fmt::println("    [{}] = 0x{:X}", dbg, dbgTarget);
                            }
                            
                            std::vector<uint32_t> targets;
                            for (size_t j = 0; j < maxEntries; j++)
                            {
                                uint32_t target = *reinterpret_cast<const uint32_t*>(tableData + j * 4);
                                // Targets must be in code sections
                                const SectionInfo* targetSec = getSectionForAddr(target);
                                if (!targetSec)
                                {
                                    //fmt::println("    Entry {} (0x{:X}) not in code section, stopping", j, target);
                                    break;
                                }
                                if (target < fn.base - 0x1000 || target > fn.base + 0x10000)
                                {
                                    //fmt::println("    Entry {} (0x{:X}) out of range from fn 0x{:X}, stopping", j, target, fn.base);
                                    break;
                                }
                                workList.push_back(target);
                                targets.push_back(target);
                            }
                            
                            //fmt::println("    Total valid entries: {}", targets.size());
                            
                            // Store the detected switch table in config for recompilation
                            if (!targets.empty() && config.switchTables.find(addr) == config.switchTables.end())
                            {
                                X86RecompilerSwitchTable switchTable;
                                switchTable.reg = static_cast<uint32_t>(op.index);
                                switchTable.defaultLabel = 0;
                                switchTable.labels = targets;
                                config.switchTables.emplace(addr, std::move(switchTable));
                            }
                            
                            // Mark all bytes in the switch table data as covered
                            // This prevents false functions from being detected in table data
                            size_t validEntries = targets.size();
                            for (size_t j = 0; j < validEntries * 4; j++)
                            {
                                uint32_t tableByteAddr = tableAddr + j;
                                if (tableByteAddr != fn.base && addrToFunc.find(tableByteAddr) == addrToFunc.end())
                                {
                                    addrToFunc[tableByteAddr] = fn.base;
                                }
                            }
                        }
                    }
                    // NOTE: JmpIndirect does NOT add addr + len - control never falls through
                }
                else if (insn.type == x86::InsnType::Jmp)
                {
                    // Non-relative Jmp (call reg, call [mem]) - also a terminator
                    // The target is unknown at static analysis time, so don't add fallthrough
                }
                else if (insn.type != x86::InsnType::Ret && 
                         insn.type != x86::InsnType::Int3)
                {
                    workList.push_back(addr + len);
                }
            }
        }
        
        // Remove functions whose start address is reachable from an earlier function
        // EXCEPT for manually-specified functions from TOML - always keep those
        std::vector<Function> filteredFunctions;
        size_t removed = 0;
        
        for (const auto& fn : functions)
        {
            // Check if this is a manually-specified function
            bool isManualFunction = config.functions.find(fn.base) != config.functions.end();
            
            auto it = addrToFunc.find(fn.base);
            if (!isManualFunction && it != addrToFunc.end() && it->second < fn.base)
            {
                // This function's start is reachable from an earlier function
                // and it's not manually specified, so remove it
                removed++;
                fmt::println("  Removing false positive: 0x{:X} (covered by 0x{:X})", fn.base, it->second);
                auto symIt = image.symbols.find(fn.base);
                if (symIt != image.symbols.end())
                    image.symbols.erase(symIt);
            }
            else if (isManualFunction && it != addrToFunc.end() && it->second < fn.base)
            {
                fmt::println("  Keeping manual function 0x{:X} despite coverage by 0x{:X}", fn.base, it->second);
            }
            else
            {
                filteredFunctions.push_back(fn);
            }
        }
        
        if (removed > 0)
        {
            fmt::println("Phase 5: Removed {} false positive functions (covered by earlier functions)", removed);
            functions = std::move(filteredFunctions);
        }
    }
    
    // Recalculate function sizes after removing false positives
    // This includes following switch table entries for indirect jumps
    for (size_t i = 0; i < functions.size(); i++)
    {
        const SectionInfo* sec = getSectionForAddr(functions[i].base);
        if (!sec) continue;
        
        std::set<uint32_t> funcAddrs;
        std::vector<uint32_t> workList;
        workList.push_back(functions[i].base);
        uint32_t maxAddr = functions[i].base;
        
        while (!workList.empty())
        {
            uint32_t addr = workList.back();
            workList.pop_back();
            
            if (funcAddrs.count(addr) || addr < sec->base || addr >= sec->base + sec->size)
                continue;
            funcAddrs.insert(addr);
            
            const uint8_t* p = sec->data + (addr - sec->base);
            x86::Insn insn;
            int len = x86::Disassemble(p, sec->size - (addr - sec->base), addr, insn);
            if (len <= 0) continue;
            
            uint32_t endAddr = addr + len;
            if (endAddr > maxAddr)
                maxAddr = endAddr;
            
            if (insn.type == x86::InsnType::Jcc && insn.is_branch_relative)
            {
                workList.push_back(insn.branch_target);
                workList.push_back(addr + len);
            }
            else if (insn.type == x86::InsnType::Jmp && insn.is_branch_relative)
            {
                workList.push_back(insn.branch_target);
            }
            else if (insn.type == x86::InsnType::JmpIndirect)
            {
                // Try to detect and read switch table
                // Pattern: jmp dword ptr [reg*4 + tableAddr]
                const auto& op = insn.op[0];
                if (op.type == x86::OpType::Mem && op.scale == 4 && op.base == x86::X86_REG_NONE)
                {
                    // This looks like a switch table: jmp [reg*4 + disp32]
                    uint32_t tableAddr = static_cast<uint32_t>(op.disp);
                    // Use getAnySectionForAddr since jump table data may be outside code boundaries
                    const SectionInfo* tableSec = getAnySectionForAddr(tableAddr);
                    
                    if (tableSec)
                    {
                        // Read switch table entries
                        // We don't know the exact count, so read until we hit invalid entries
                        const uint8_t* tableData = tableSec->data + (tableAddr - tableSec->base);
                        size_t maxEntries = (tableSec->size - (tableAddr - tableSec->base)) / 4;
                        if (maxEntries > 256) maxEntries = 256;  // Reasonable limit
                        
                        std::vector<uint32_t> targets;
                        for (size_t j = 0; j < maxEntries; j++)
                        {
                            uint32_t target = *reinterpret_cast<const uint32_t*>(tableData + j * 4);
                            
                            // Validate: target should be in a code section and near this function
                            const SectionInfo* targetSec = getSectionForAddr(target);
                            if (!targetSec)
                                break;
                            
                            // Target should be reasonably close to function start (within 64KB)
                            if (target < functions[i].base - 0x1000 || target > functions[i].base + 0x10000)
                                break;
                            
                            // Looks valid, add to worklist
                            workList.push_back(target);
                            targets.push_back(target);
                        }
                        
                        // Store detected switch table in config
                        if (!targets.empty() && config.switchTables.find(addr) == config.switchTables.end())
                        {
                            X86RecompilerSwitchTable switchTable;
                            switchTable.reg = static_cast<uint32_t>(op.index);
                            switchTable.defaultLabel = 0;
                            switchTable.labels = std::move(targets);
                            config.switchTables.emplace(addr, std::move(switchTable));
                        }
                    }
                }
            }
            else if (insn.type != x86::InsnType::Ret && 
                     insn.type != x86::InsnType::Int3)
            {
                workList.push_back(addr + len);
            }
        }
        
        functions[i].size = maxAddr - functions[i].base;
        
        // Update symbol
        auto it = image.symbols.find(functions[i].base);
        if (it != image.symbols.end())
        {
            Symbol updated = *it;
            updated.size = functions[i].size;
            image.symbols.erase(it);
            image.symbols.insert(updated);
        }
    }

    // Build the functionEntryPoints set for tail call detection during recompilation
    functionEntryPoints.clear();
    for (const auto& fn : functions)
    {
        functionEntryPoints.insert(fn.base);
    }

    fmt::println("Found {} functions", functions.size());
    
    // Verify all manual functions are present
    // if (!config.functions.empty())
    // {
    //     fmt::println("\nVerifying manual functions:");
    //     for (const auto& [addr, size] : config.functions)
    //     {
    //         bool found = false;
    //         for (const auto& fn : functions)
    //         {
    //             if (fn.base == addr)
    //             {
    //                 found = true;
    //                 break;
    //             }
    //         }
    //         if (found)
    //         {
    //             fmt::println("  ✓ 0x{:X} present", addr);
    //         }
    //         else
    //         {
    //             fmt::println("  ✗ 0x{:X} MISSING - this function was removed during analysis!", addr);
    //         }
    //     }
    // }
}

std::string X86Recompiler::FormatOperand(const x86::Operand& op, int size, X86RecompilerLocalVariables& locals)
{
    switch (op.type)
    {
    case x86::OpType::Reg:
    {
        // Mark register as used
        switch (op.reg)
        {
        case x86::EAX: locals.eax = true; break;
        case x86::ECX: locals.ecx = true; break;
        case x86::EDX: locals.edx = true; break;
        case x86::EBX: locals.ebx = true; break;
        case x86::ESP: locals.esp = true; break;
        case x86::EBP: locals.ebp = true; break;
        case x86::ESI: locals.esi = true; break;
        case x86::EDI: locals.edi = true; break;
        }

        if (size == 4)
            return fmt::format("ctx.{}.u32", GetRegName32(op.reg));
        else if (size == 2)
            return fmt::format("ctx.{}.u16", GetRegName32(op.reg));
        else if (size == 1)
            return fmt::format("ctx.{}.u8", GetRegName32(op.reg));
        break;
    }
    case x86::OpType::Imm:
        if (size == 4)
            return fmt::format("0x{:X}u", op.imm);
        else if (size == 2)
            return fmt::format("0x{:X}u", op.imm & 0xFFFF);
        else
            return fmt::format("0x{:X}u", op.imm & 0xFF);

    case x86::OpType::Mem:
    case x86::OpType::MemDisp:
    {
        std::string addr;
        
        if (op.base != x86::X86_REG_NONE)
        {
            // Mark base register as used
            switch (op.base)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESP: locals.esp = true; break;
            case x86::EBP: locals.ebp = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            addr = fmt::format("ctx.{}.u32", GetRegName32(op.base));
        }
        
        if (op.index != x86::X86_REG_NONE)
        {
            // Mark index register as used
            switch (op.index)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            
            std::string indexPart = fmt::format("ctx.{}.u32", GetRegName32(op.index));
            if (op.scale > 1)
                indexPart = fmt::format("({} * {})", indexPart, op.scale);
            
            if (addr.empty())
                addr = indexPart;
            else
                addr = fmt::format("({} + {})", addr, indexPart);
        }
        
        if (op.disp != 0 || addr.empty())
        {
            if (addr.empty())
                addr = fmt::format("0x{:X}u", static_cast<uint32_t>(op.disp));
            else if (op.disp > 0)
                addr = fmt::format("({} + 0x{:X}u)", addr, op.disp);
            else
                addr = fmt::format("({} - 0x{:X}u)", addr, -op.disp);
        }
        
        const char* loadMacro;
        if (size == 4)
            loadMacro = "X86_LOAD_U32";
        else if (size == 2)
            loadMacro = "X86_LOAD_U16";
        else
            loadMacro = "X86_LOAD_U8";
        
        return fmt::format("{}({})", loadMacro, addr);
    }
    
    default:
        return "/* unknown operand */";
    }
    
    return "/* error */";
}

std::string X86Recompiler::FormatOperandRead(const x86::Operand& op, int size, X86RecompilerLocalVariables& locals)
{
    return FormatOperand(op, size, locals);
}

std::string X86Recompiler::FormatOperandWrite(const x86::Operand& op, const std::string& value, int size, X86RecompilerLocalVariables& locals)
{
    switch (op.type)
    {
    case x86::OpType::Reg:
    {
        // Mark register as used
        switch (op.reg)
        {
        case x86::EAX: locals.eax = true; break;
        case x86::ECX: locals.ecx = true; break;
        case x86::EDX: locals.edx = true; break;
        case x86::EBX: locals.ebx = true; break;
        case x86::ESP: locals.esp = true; break;
        case x86::EBP: locals.ebp = true; break;
        case x86::ESI: locals.esi = true; break;
        case x86::EDI: locals.edi = true; break;
        }

        if (size == 4)
            return fmt::format("ctx.{}.u32 = {}", GetRegName32(op.reg), value);
        else if (size == 2)
            return fmt::format("ctx.{}.u16 = static_cast<uint16_t>({})", GetRegName32(op.reg), value);
        else
            return fmt::format("ctx.{}.u8 = static_cast<uint8_t>({})", GetRegName32(op.reg), value);
    }
    
    case x86::OpType::Mem:
    case x86::OpType::MemDisp:
    {
        std::string addr;
        
        if (op.base != x86::X86_REG_NONE)
        {
            switch (op.base)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESP: locals.esp = true; break;
            case x86::EBP: locals.ebp = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            addr = fmt::format("ctx.{}.u32", GetRegName32(op.base));
        }
        
        if (op.index != x86::X86_REG_NONE)
        {
            switch (op.index)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            
            std::string indexPart = fmt::format("ctx.{}.u32", GetRegName32(op.index));
            if (op.scale > 1)
                indexPart = fmt::format("({} * {})", indexPart, op.scale);
            
            if (addr.empty())
                addr = indexPart;
            else
                addr = fmt::format("({} + {})", addr, indexPart);
        }
        
        if (op.disp != 0 || addr.empty())
        {
            if (addr.empty())
                addr = fmt::format("0x{:X}u", static_cast<uint32_t>(op.disp));
            else if (op.disp > 0)
                addr = fmt::format("({} + 0x{:X}u)", addr, op.disp);
            else
                addr = fmt::format("({} - 0x{:X}u)", addr, -op.disp);
        }
        
        const char* storeMacro;
        if (size == 4)
            storeMacro = "X86_STORE_U32";
        else if (size == 2)
            storeMacro = "X86_STORE_U16";
        else
            storeMacro = "X86_STORE_U8";
        
        return fmt::format("{}({}, {})", storeMacro, addr, value);
    }
    
    default:
        return fmt::format("/* unknown operand = {} */", value);
    }
}

std::string X86Recompiler::FormatXmmOperandRead(const x86::Operand& op, X86RecompilerLocalVariables& locals)
{
    if (op.type == x86::OpType::Reg)
    {
        // XMM register
        if (op.reg < 8) locals.xmm[op.reg] = true;
        return fmt::format("ctx.{}.m128", GetXmmRegName(op.reg));
    }
    else if (op.type == x86::OpType::Mem || op.type == x86::OpType::MemDisp)
    {
        // Memory operand - load 128 bits
        std::string addr;
        
        if (op.base != x86::X86_REG_NONE)
        {
            switch (op.base)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESP: locals.esp = true; break;
            case x86::EBP: locals.ebp = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            addr = fmt::format("ctx.{}.u32", GetRegName32(op.base));
        }
        
        if (op.index != x86::X86_REG_NONE)
        {
            switch (op.index)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            
            std::string indexPart = fmt::format("ctx.{}.u32", GetRegName32(op.index));
            if (op.scale > 1)
                indexPart = fmt::format("({} * {})", indexPart, op.scale);
            
            if (addr.empty())
                addr = indexPart;
            else
                addr = fmt::format("({} + {})", addr, indexPart);
        }
        
        if (op.disp != 0 || addr.empty())
        {
            if (addr.empty())
                addr = fmt::format("0x{:X}u", static_cast<uint32_t>(op.disp));
            else if (op.disp > 0)
                addr = fmt::format("({} + 0x{:X}u)", addr, op.disp);
            else
                addr = fmt::format("({} - 0x{:X}u)", addr, -op.disp);
        }
        
        return fmt::format("X86_LOAD_XMM({})", addr);
    }
    
    return "/* unknown XMM operand */";
}

std::string X86Recompiler::FormatXmmOperandWrite(const x86::Operand& op, const std::string& value, X86RecompilerLocalVariables& locals)
{
    if (op.type == x86::OpType::Reg)
    {
        // XMM register
        if (op.reg < 8) locals.xmm[op.reg] = true;
        return fmt::format("ctx.{}.m128 = {}", GetXmmRegName(op.reg), value);
    }
    else if (op.type == x86::OpType::Mem || op.type == x86::OpType::MemDisp)
    {
        // Memory operand - store 128 bits
        std::string addr;
        
        if (op.base != x86::X86_REG_NONE)
        {
            switch (op.base)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESP: locals.esp = true; break;
            case x86::EBP: locals.ebp = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            addr = fmt::format("ctx.{}.u32", GetRegName32(op.base));
        }
        
        if (op.index != x86::X86_REG_NONE)
        {
            switch (op.index)
            {
            case x86::EAX: locals.eax = true; break;
            case x86::ECX: locals.ecx = true; break;
            case x86::EDX: locals.edx = true; break;
            case x86::EBX: locals.ebx = true; break;
            case x86::ESI: locals.esi = true; break;
            case x86::EDI: locals.edi = true; break;
            }
            
            std::string indexPart = fmt::format("ctx.{}.u32", GetRegName32(op.index));
            if (op.scale > 1)
                indexPart = fmt::format("({} * {})", indexPart, op.scale);
            
            if (addr.empty())
                addr = indexPart;
            else
                addr = fmt::format("({} + {})", addr, indexPart);
        }
        
        if (op.disp != 0 || addr.empty())
        {
            if (addr.empty())
                addr = fmt::format("0x{:X}u", static_cast<uint32_t>(op.disp));
            else if (op.disp > 0)
                addr = fmt::format("({} + 0x{:X}u)", addr, op.disp);
            else
                addr = fmt::format("({} - 0x{:X}u)", addr, -op.disp);
        }
        
        return fmt::format("X86_STORE_XMM({}, {})", addr, value);
    }
    
    return fmt::format("/* unknown XMM operand = {} */", value);
}

std::string X86Recompiler::FormatMemoryAddress(const x86::Operand& op, X86RecompilerLocalVariables& locals)
{
    std::string addr;
    
    if (op.base != x86::X86_REG_NONE)
    {
        switch (op.base)
        {
        case x86::EAX: locals.eax = true; break;
        case x86::ECX: locals.ecx = true; break;
        case x86::EDX: locals.edx = true; break;
        case x86::EBX: locals.ebx = true; break;
        case x86::ESP: locals.esp = true; break;
        case x86::EBP: locals.ebp = true; break;
        case x86::ESI: locals.esi = true; break;
        case x86::EDI: locals.edi = true; break;
        }
        addr = fmt::format("ctx.{}.u32", GetRegName32(op.base));
    }
    
    if (op.index != x86::X86_REG_NONE)
    {
        switch (op.index)
        {
        case x86::EAX: locals.eax = true; break;
        case x86::ECX: locals.ecx = true; break;
        case x86::EDX: locals.edx = true; break;
        case x86::EBX: locals.ebx = true; break;
        case x86::ESI: locals.esi = true; break;
        case x86::EDI: locals.edi = true; break;
        }
        
        std::string indexPart = fmt::format("ctx.{}.u32", GetRegName32(op.index));
        if (op.scale > 1)
            indexPart = fmt::format("({} * {})", indexPart, op.scale);
        
        if (addr.empty())
            addr = indexPart;
        else
            addr = fmt::format("({} + {})", addr, indexPart);
    }
    
    if (op.disp != 0 || addr.empty())
    {
        if (addr.empty())
            addr = fmt::format("0x{:X}u", static_cast<uint32_t>(op.disp));
        else if (op.disp > 0)
            addr = fmt::format("({} + 0x{:X}u)", addr, op.disp);
        else
            addr = fmt::format("({} - 0x{:X}u)", addr, -op.disp);
    }
    
    return addr;
}

bool X86Recompiler::RecompileInstruction(
    const Function& fn,
    uint32_t address,
    const x86::Insn& insn,
    const uint8_t* data,
    std::unordered_map<uint32_t, X86RecompilerSwitchTable>::iterator& switchTable,
    X86RecompilerLocalVariables& localVariables,
    bool needsFallThroughLabel,
    uint32_t effectiveBase,
    uint32_t effectiveEnd)
{
    // Print instruction as comment
    print("\t// {:08X}: ", address);
    for (int i = 0; i < insn.length && i < 8; i++)
        print("{:02X} ", data[i]);
    println("");

    auto printFunctionCall = [&, address](uint32_t target)
    {
        // Check if target is within current function (call to a label, not a function)
        // Use TOML-specified function size as the true boundary, not just effectiveEnd
        // (effectiveEnd may be smaller if SEH handlers aren't reached via normal control flow)
        uint32_t functionSize = fn.size;
        auto tomlIt = config.functions.find(fn.base);
        if (tomlIt != config.functions.end())
        {
            functionSize = tomlIt->second;
        }
        uint32_t tomlEnd = fn.base + functionSize;
        
        // Check if target is in main function body
        bool isInMainBody = (target >= fn.base && target < tomlEnd);
        
        // Check if target is in a function chunk
        bool isInChunk = false;
        auto chunksIt = config.functionChunks.find(fn.base);
        if (chunksIt != config.functionChunks.end())
        {
            for (const auto& [chunkAddr, chunkSize] : chunksIt->second)
            {
                if (target >= chunkAddr && target < chunkAddr + chunkSize)
                {
                    isInChunk = true;
                    break;
                }
            }
        }
        
        if (isInMainBody || isInChunk)
        {
            // This is a call to a label within the current function or its chunks
            // Push return address and goto the label
            localVariables.esp = true;
            println("\tctx.esp.u32 -= 4;");
            println("\tX86_STORE_U32(ctx.esp.u32, 0x{:X});", address + insn.length); // Return address
            println("\tgoto loc_{:X};", target);
            return;
        }
        
        auto targetSymbol = image.symbols.find(target);
        if (targetSymbol != image.symbols.end() && targetSymbol->address == target && targetSymbol->type == Symbol_Function)
        {
            println("\t{}(ctx, base);", targetSymbol->name);
        }
        else
        {
            // Check if this might be a function chunk we missed
            bool isInCodeSection = false;
            for (const auto& section : image.sections)
            {
                if ((section.flags & SectionFlags_Code) && 
                    target >= section.base && target < section.base + section.size)
                {
                    isInCodeSection = true;
                    break;
                }
            }
            
            if (isInCodeSection)
            {
                // Generate a call anyway - assume it's a function chunk
                println("\tsub_{:X}(ctx, base);", target);
                println("\t// WARNING: Function chunk at {:X} - may need manual verification", target);
            }
            else
            {
                println("\t// ERROR: Unknown function at {:X}", target);
            }
        }
    };

    auto printConditionalJump = [&](const char* cond, uint32_t target)
    {
        // Check if target is in a function chunk
        bool isInChunk = false;
        auto chunksIt = config.functionChunks.find(fn.base);
        if (chunksIt != config.functionChunks.end())
        {
            for (const auto& [chunkAddr, chunkSize] : chunksIt->second)
            {
                if (target >= chunkAddr && target < chunkAddr + chunkSize)
                {
                    isInChunk = true;
                    break;
                }
            }
        }
        
        // Check if target is outside effective function range OR is another function's entry (tail call)
        bool isTailCall = (target < effectiveBase || target >= effectiveEnd) && !isInChunk;
        if (!isTailCall && functionEntryPoints.count(target) && target != fn.base && !isInChunk)
        {
            // Target is within "function range" but is actually another function - tail call
            isTailCall = true;
        }
        
        if (isTailCall)
        {
            // Jump outside function - need to verify target is actually a function
            if (functionEntryPoints.count(target))
            {
                // Target is a known function entry - emit tail call
                println("\tif ({}) {{", cond);
                printFunctionCall(target);
                println("\t\treturn;");
                println("\t}}");
            }
            else
            {
                // Target is not a function entry - this is likely a function chunk
                // that wasn't detected. Emit the call with a warning.
                println("\tif ({}) {{", cond);
                printFunctionCall(target);
                println("\t// WARNING: Function chunk at {:X} - may need manual verification", target);
                println("\t\treturn;");
                println("\t}}");
            }
        }
        else
        {
            println("\tif ({}) goto loc_{:X};", cond, target);
        }
    };

    // Get condition string from condition code
    auto getConditionString = [&](x86::Condition cond) -> std::string
    {
        localVariables.eflags = true;
        switch (cond)
        {
        case x86::Condition::O:  return "ctx.eflags.of";
        case x86::Condition::NO: return "!ctx.eflags.of";
        case x86::Condition::B:  return "ctx.eflags.cf";
        case x86::Condition::NB: return "!ctx.eflags.cf";
        case x86::Condition::E:  return "ctx.eflags.zf";
        case x86::Condition::NE: return "!ctx.eflags.zf";
        case x86::Condition::BE: return "(ctx.eflags.cf || ctx.eflags.zf)";
        case x86::Condition::A:  return "(!ctx.eflags.cf && !ctx.eflags.zf)";
        case x86::Condition::S:  return "ctx.eflags.sf";
        case x86::Condition::NS: return "!ctx.eflags.sf";
        case x86::Condition::P:  return "ctx.eflags.pf";
        case x86::Condition::NP: return "!ctx.eflags.pf";
        case x86::Condition::L:  return "(ctx.eflags.sf != ctx.eflags.of)";
        case x86::Condition::GE: return "(ctx.eflags.sf == ctx.eflags.of)";
        case x86::Condition::LE: return "(ctx.eflags.zf || (ctx.eflags.sf != ctx.eflags.of))";
        case x86::Condition::G:  return "(!ctx.eflags.zf && (ctx.eflags.sf == ctx.eflags.of))";
        default: return "/* unknown condition */";
        }
    };

    switch (insn.type)
    {
    case x86::InsnType::Push:
        if (insn.op[0].type == x86::OpType::Reg)
        {
            localVariables.esp = true;
            println("\tctx.esp.u32 -= 4;");
            println("\tX86_STORE_U32(ctx.esp.u32, {});", FormatOperandRead(insn.op[0], 4, localVariables));
        }
        else if (insn.op[0].type == x86::OpType::Imm)
        {
            localVariables.esp = true;
            println("\tctx.esp.u32 -= 4;");
            println("\tX86_STORE_U32(ctx.esp.u32, 0x{:X}u);", insn.op[0].imm);
        }
        else
        {
            localVariables.esp = true;
            println("\tctx.esp.u32 -= 4;");
            println("\tX86_STORE_U32(ctx.esp.u32, {});", FormatOperandRead(insn.op[0], 4, localVariables));
        }
        break;

    case x86::InsnType::Pop:
        if (insn.op[0].type == x86::OpType::Reg)
        {
            localVariables.esp = true;
            println("\t{};", FormatOperandWrite(insn.op[0], "X86_LOAD_U32(ctx.esp.u32)", 4, localVariables));
            println("\tctx.esp.u32 += 4;");
        }
        else
        {
            localVariables.esp = true;
            localVariables.temp = true;
            println("\ttemp = X86_LOAD_U32(ctx.esp.u32);");
            println("\tctx.esp.u32 += 4;");
            println("\t{};", FormatOperandWrite(insn.op[0], "temp", 4, localVariables));
        }
        break;

    case x86::InsnType::Mov:
        println("\t{};", FormatOperandWrite(insn.op[0], FormatOperandRead(insn.op[1], 4, localVariables), 4, localVariables));
        break;

    case x86::InsnType::Add:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], 4, localVariables);
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0], 
            fmt::format("x86_add<int32_t>({}, {}, ctx.eflags)", dst, src), 4, localVariables));
        break;
    }

    case x86::InsnType::Sub:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], 4, localVariables);
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_sub<int32_t>({}, {}, ctx.eflags)", dst, src), 4, localVariables));
        break;
    }

    case x86::InsnType::And:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string src = FormatOperandRead(insn.op[1], insn.operandSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_and<int32_t>({}, {}, ctx.eflags)", dst, src), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Or:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string src = FormatOperandRead(insn.op[1], insn.operandSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_or<int32_t>({}, {}, ctx.eflags)", dst, src), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Xor:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string src = FormatOperandRead(insn.op[1], insn.operandSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_xor<int32_t>({}, {}, ctx.eflags)", dst, src), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Inc:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_inc<int32_t>({}, ctx.eflags)", dst), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Dec:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_dec<int32_t>({}, ctx.eflags)", dst), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Neg:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_neg<int32_t>({}, ctx.eflags)", dst), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Not:
    {
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("~({})", dst), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Mul:
    {
        // Unsigned multiply: EDX:EAX = EAX * src
        localVariables.eax = true;
        localVariables.edx = true;
        localVariables.eflags = true;
        std::string src = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        println("\t{{");
        println("\t\tuint64_t result = static_cast<uint64_t>(ctx.eax.u32) * static_cast<uint64_t>({});", src);
        println("\t\tctx.eax.u32 = static_cast<uint32_t>(result);");
        println("\t\tctx.edx.u32 = static_cast<uint32_t>(result >> 32);");
        println("\t\tctx.eflags.of = ctx.eflags.cf = (ctx.edx.u32 != 0);");
        println("\t}}");
        break;
    }

    case x86::InsnType::Imul:
    {
        localVariables.eflags = true;
        if (insn.op[2].type != x86::OpType::None)
        {
            // Three-operand form: IMUL r32, r/m32, imm
            std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
            std::string imm = FormatOperandRead(insn.op[2], 4, localVariables);
            println("\t{{");
            println("\t\tint64_t result = static_cast<int64_t>(static_cast<int32_t>({})) * static_cast<int64_t>(static_cast<int32_t>({}));", src, imm);
            println("\t\t{};", FormatOperandWrite(insn.op[0], "static_cast<uint32_t>(result)", 4, localVariables));
            println("\t\tctx.eflags.of = ctx.eflags.cf = (result != static_cast<int32_t>(result));");
            println("\t}}");
        }
        else if (insn.op[1].type != x86::OpType::None)
        {
            // Two-operand form: IMUL r32, r/m32
            std::string dst = FormatOperandRead(insn.op[0], 4, localVariables);
            std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
            println("\t{{");
            println("\t\tint64_t result = static_cast<int64_t>(static_cast<int32_t>({})) * static_cast<int64_t>(static_cast<int32_t>({}));", dst, src);
            println("\t\t{};", FormatOperandWrite(insn.op[0], "static_cast<uint32_t>(result)", 4, localVariables));
            println("\t\tctx.eflags.of = ctx.eflags.cf = (result != static_cast<int32_t>(result));");
            println("\t}}");
        }
        else
        {
            // One-operand form: IMUL r/m32 -> EDX:EAX = EAX * src
            localVariables.eax = true;
            localVariables.edx = true;
            std::string src = FormatOperandRead(insn.op[0], 4, localVariables);
            println("\t{{");
            println("\t\tint64_t result = static_cast<int64_t>(static_cast<int32_t>(ctx.eax.u32)) * static_cast<int64_t>(static_cast<int32_t>({}));", src);
            println("\t\tctx.eax.u32 = static_cast<uint32_t>(result);");
            println("\t\tctx.edx.u32 = static_cast<uint32_t>(result >> 32);");
            println("\t\tctx.eflags.of = ctx.eflags.cf = (result != static_cast<int32_t>(result));");
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Div:
    {
        // Unsigned divide: EAX = EDX:EAX / src, EDX = EDX:EAX % src
        localVariables.eax = true;
        localVariables.edx = true;
        std::string src = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        println("\t{{");
        println("\t\tuint64_t dividend = (static_cast<uint64_t>(ctx.edx.u32) << 32) | ctx.eax.u32;");
        println("\t\tuint32_t divisor = {};", src);
        println("\t\tctx.eax.u32 = static_cast<uint32_t>(dividend / divisor);");
        println("\t\tctx.edx.u32 = static_cast<uint32_t>(dividend % divisor);");
        println("\t}}");
        break;
    }

    case x86::InsnType::Idiv:
    {
        // Signed divide: EAX = EDX:EAX / src, EDX = EDX:EAX % src
        localVariables.eax = true;
        localVariables.edx = true;
        std::string src = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        println("\t{{");
        println("\t\tint64_t dividend = static_cast<int64_t>((static_cast<uint64_t>(ctx.edx.u32) << 32) | ctx.eax.u32);");
        println("\t\tint32_t divisor = static_cast<int32_t>({});", src);
        println("\t\tctx.eax.u32 = static_cast<uint32_t>(static_cast<int32_t>(dividend / divisor));");
        println("\t\tctx.edx.u32 = static_cast<uint32_t>(static_cast<int32_t>(dividend % divisor));");
        println("\t}}");
        break;
    }

    case x86::InsnType::Cwde:
        // Sign-extend AX into EAX
        localVariables.eax = true;
        println("\tctx.eax.u32 = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(ctx.eax.u16)));");
        break;

    case x86::InsnType::Cdq:
        // Sign-extend EAX into EDX:EAX
        localVariables.eax = true;
        localVariables.edx = true;
        println("\tctx.edx.u32 = (ctx.eax.u32 & 0x80000000) ? 0xFFFFFFFF : 0;");
        break;

    case x86::InsnType::Lahf:
        // Load AH from low byte of EFLAGS (SF:ZF:0:AF:0:PF:1:CF)
        localVariables.eax = true;
        localVariables.eflags = true;
        println("\tctx.eax.bytes.hi = (ctx.eflags.sf << 7) | (ctx.eflags.zf << 6) | (ctx.eflags.af << 4) | (ctx.eflags.pf << 2) | 0x02 | ctx.eflags.cf;");
        break;

    case x86::InsnType::Sahf:
        // Store AH into low byte of EFLAGS
        localVariables.eax = true;
        localVariables.eflags = true;
        println("\tctx.eflags.sf = (ctx.eax.bytes.hi >> 7) & 1;");
        println("\tctx.eflags.zf = (ctx.eax.bytes.hi >> 6) & 1;");
        println("\tctx.eflags.af = (ctx.eax.bytes.hi >> 4) & 1;");
        println("\tctx.eflags.pf = (ctx.eax.bytes.hi >> 2) & 1;");
        println("\tctx.eflags.cf = ctx.eax.bytes.hi & 1;");
        break;

    case x86::InsnType::Pushad:
    {
        // Push EAX, ECX, EDX, EBX, original ESP, EBP, ESI, EDI
        localVariables.eax = true;
        localVariables.ecx = true;
        localVariables.edx = true;
        localVariables.ebx = true;
        localVariables.esp = true;
        localVariables.ebp = true;
        localVariables.esi = true;
        localVariables.edi = true;
        localVariables.temp = true;
        println("\ttemp = ctx.esp.u32;");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, ctx.eax.u32);");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, ctx.ecx.u32);");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, ctx.edx.u32);");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, ctx.ebx.u32);");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, temp);");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, ctx.ebp.u32);");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, ctx.esi.u32);");
        println("\tctx.esp.u32 -= 4; X86_STORE_U32(ctx.esp.u32, ctx.edi.u32);");
        break;
    }

    case x86::InsnType::Popad:
    {
        // Pop EDI, ESI, EBP, skip ESP, EBX, EDX, ECX, EAX
        localVariables.eax = true;
        localVariables.ecx = true;
        localVariables.edx = true;
        localVariables.ebx = true;
        localVariables.esp = true;
        localVariables.ebp = true;
        localVariables.esi = true;
        localVariables.edi = true;
        println("\tctx.edi.u32 = X86_LOAD_U32(ctx.esp.u32); ctx.esp.u32 += 4;");
        println("\tctx.esi.u32 = X86_LOAD_U32(ctx.esp.u32); ctx.esp.u32 += 4;");
        println("\tctx.ebp.u32 = X86_LOAD_U32(ctx.esp.u32); ctx.esp.u32 += 4;");
        println("\tctx.esp.u32 += 4; // Skip saved ESP");
        println("\tctx.ebx.u32 = X86_LOAD_U32(ctx.esp.u32); ctx.esp.u32 += 4;");
        println("\tctx.edx.u32 = X86_LOAD_U32(ctx.esp.u32); ctx.esp.u32 += 4;");
        println("\tctx.ecx.u32 = X86_LOAD_U32(ctx.esp.u32); ctx.esp.u32 += 4;");
        println("\tctx.eax.u32 = X86_LOAD_U32(ctx.esp.u32); ctx.esp.u32 += 4;");
        break;
    }

    case x86::InsnType::Enter:
    {
        // Create stack frame: push ebp, mov ebp, esp, sub esp, imm16
        localVariables.esp = true;
        localVariables.ebp = true;
        uint32_t frameSize = insn.op[0].imm;
        uint32_t nestingLevel = insn.op[1].imm & 0x1F;
        println("\tctx.esp.u32 -= 4;");
        println("\tX86_STORE_U32(ctx.esp.u32, ctx.ebp.u32);");
        println("\tctx.ebp.u32 = ctx.esp.u32;");
        if (frameSize > 0)
            println("\tctx.esp.u32 -= 0x{:X};", frameSize);
        if (nestingLevel > 0)
            println("\t// ENTER nesting level {} not fully implemented", nestingLevel);
        break;
    }

    case x86::InsnType::Bound:
        // BOUND checks if a register value is within bounds
        // Typically raises #BR exception if out of bounds - we'll ignore for now
        println("\t// BOUND instruction - bounds check ignored");
        break;

    case x86::InsnType::Hlt:
        // HLT - Halt the processor. In recompiled code, this is typically an error
        println("\t// HLT instruction - processor halt");
        break;

    case x86::InsnType::Aaa:
    case x86::InsnType::Aas:
    case x86::InsnType::Daa:
    case x86::InsnType::Das:
        // Legacy BCD arithmetic instructions - rarely used
        localVariables.eax = true;
        localVariables.eflags = true;
        println("\t// BCD adjustment instruction - not implemented");
        break;

    case x86::InsnType::Retf:
        // Far return - pops CS:EIP from stack
        // In flat memory model, treat as regular return
        localVariables.esp = true;
        println("\t// Far return - treating as near return");
        println("\treturn;");
        break;

    case x86::InsnType::In:
    {
        // IN instruction - reads from I/O port into AL/AX/EAX
        // Port is either immediate or in DX
        localVariables.eax = true;
        std::string port;
        if (insn.op[1].type == x86::OpType::Imm)
            port = fmt::format("0x{:X}", insn.op[1].imm);
        else
        {
            localVariables.edx = true;
            port = "ctx.edx.u16";
        }
        
        if (insn.operandSize == 1)
            println("\tctx.eax.u8 = X86_PORT_IN_U8({});", port);
        else if (insn.operandSize == 2)
            println("\tctx.eax.u16 = X86_PORT_IN_U16({});", port);
        else
            println("\tctx.eax.u32 = X86_PORT_IN_U32({});", port);
        break;
    }

    case x86::InsnType::Out:
    {
        // OUT instruction - writes to I/O port from AL/AX/EAX
        // Port is either immediate or in DX
        localVariables.eax = true;
        std::string port;
        if (insn.op[0].type == x86::OpType::Imm)
            port = fmt::format("0x{:X}", insn.op[0].imm);
        else
        {
            localVariables.edx = true;
            port = "ctx.edx.u16";
        }
        
        if (insn.operandSize == 1)
            println("\tX86_PORT_OUT_U8({}, ctx.eax.u8);", port);
        else if (insn.operandSize == 2)
            println("\tX86_PORT_OUT_U16({}, ctx.eax.u16);", port);
        else
            println("\tX86_PORT_OUT_U32({}, ctx.eax.u32);", port);
        break;
    }

    case x86::InsnType::Loop:
    {
        // LOOP/LOOPE/LOOPNE - decrement ECX and branch if condition met
        localVariables.ecx = true;
        println("\tctx.ecx.u32--;");
        if (insn.cond == x86::Condition::None)
        {
            // LOOP - branch if ECX != 0
            println("\tif (ctx.ecx.u32 != 0) goto loc_{:X};", insn.branch_target);
        }
        else if (insn.cond == x86::Condition::E)
        {
            // LOOPE/LOOPZ - branch if ECX != 0 and ZF == 1
            localVariables.eflags = true;
            println("\tif (ctx.ecx.u32 != 0 && ctx.eflags.zf) goto loc_{:X};", insn.branch_target);
        }
        else if (insn.cond == x86::Condition::NE)
        {
            // LOOPNE/LOOPNZ - branch if ECX != 0 and ZF == 0
            localVariables.eflags = true;
            println("\tif (ctx.ecx.u32 != 0 && !ctx.eflags.zf) goto loc_{:X};", insn.branch_target);
        }
        break;
    }

    case x86::InsnType::MovSeg:
    {
        // MOV Sreg, r/m16 (8E) or MOV r/m16, Sreg (8C)
        // Segment register encoding: 0=ES, 1=CS, 2=SS, 3=DS, 4=FS, 5=GS
        auto getSegRegName = [](int idx) -> const char* {
            switch (idx) {
                case 0: return "es";
                case 1: return "cs";
                case 2: return "ss";
                case 3: return "ds";
                case 4: return "fs";
                case 5: return "gs";
                default: return "es";  // fallback
            }
        };
        
        // Check direction based on operand types
        if (insn.op[0].type == x86::OpType::Reg && insn.op[0].reg <= 5)
        {
            // MOV Sreg, r/m16 - load segment register from r/m16
            int segIdx = static_cast<int>(insn.op[0].reg);
            std::string src = FormatOperandRead(insn.op[1], 2, localVariables);
            println("\tctx.{} = static_cast<uint16_t>({});", getSegRegName(segIdx), src);
        }
        else if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg <= 5)
        {
            // MOV r/m16, Sreg - store segment register to r/m16
            int segIdx = static_cast<int>(insn.op[1].reg);
            std::string dst = FormatOperandWrite(insn.op[0], fmt::format("ctx.{}", getSegRegName(segIdx)), 2, localVariables);
            println("\t{};", dst);
        }
        else
        {
            println("\t// MOV segment register - unknown encoding");
        }
        break;
    }

    case x86::InsnType::Clc:
        localVariables.eflags = true;
        println("\tctx.eflags.cf = 0;");
        break;

    case x86::InsnType::Stc:
        localVariables.eflags = true;
        println("\tctx.eflags.cf = 1;");
        break;

    case x86::InsnType::Cld:
        localVariables.eflags = true;
        println("\tctx.eflags.df = 0;");
        break;

    case x86::InsnType::Std:
        localVariables.eflags = true;
        println("\tctx.eflags.df = 1;");
        break;

    case x86::InsnType::Cli:
        // Clear interrupt flag - ignored in user mode
        println("\t// CLI - ignored");
        break;

    case x86::InsnType::Sti:
        // Set interrupt flag - ignored in user mode
        println("\t// STI - ignored");
        break;

    case x86::InsnType::Cmc:
        localVariables.eflags = true;
        println("\tctx.eflags.cf = !ctx.eflags.cf;");
        break;

    case x86::InsnType::Fwait:
        // FWAIT/WAIT - wait for FPU, usually a no-op in modern systems
        println("\t// FWAIT - no-op");
        break;

    case x86::InsnType::Jecxz:
        localVariables.ecx = true;
        println("\tif (ctx.ecx.u32 == 0) goto loc_{:X};", insn.branch_target);
        break;

    case x86::InsnType::Aam:
    {
        // AAM - ASCII Adjust AX After Multiply
        // AH = AL / base; AL = AL % base (base is immediate, default 10)
        localVariables.eax = true;
        localVariables.eflags = true;
        uint8_t base = (insn.op[0].type == x86::OpType::Imm) ? static_cast<uint8_t>(insn.op[0].imm) : 10;
        if (base == 0)
        {
            println("\t// AAM with base 0 - divide by zero");
        }
        else
        {
            println("\t{{");
            println("\t\tuint8_t al = ctx.eax.u8;");
            println("\t\tctx.eax.bytes.hi = al / {};", base);
            println("\t\tctx.eax.u8 = al % {};", base);
            println("\t\tctx.eflags.sf = (ctx.eax.u8 & 0x80) != 0;");
            println("\t\tctx.eflags.zf = (ctx.eax.u8 == 0);");
            println("\t\tctx.eflags.pf = !(__builtin_popcount(ctx.eax.u8) & 1);");
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Aad:
    {
        // AAD - ASCII Adjust AX Before Division
        // AL = (AH * base) + AL; AH = 0 (base is immediate, default 10)
        localVariables.eax = true;
        localVariables.eflags = true;
        uint8_t base = (insn.op[0].type == x86::OpType::Imm) ? static_cast<uint8_t>(insn.op[0].imm) : 10;
        println("\t{{");
        println("\t\tuint8_t result = (ctx.eax.bytes.hi * {}) + ctx.eax.u8;", base);
        println("\t\tctx.eax.u8 = result;");
        println("\t\tctx.eax.bytes.hi = 0;");
        println("\t\tctx.eflags.sf = (result & 0x80) != 0;");
        println("\t\tctx.eflags.zf = (result == 0);");
        println("\t\tctx.eflags.pf = !(__builtin_popcount(result) & 1);");
        println("\t}}");
        break;
    }

    case x86::InsnType::Into:
        // Interrupt on overflow - check OF flag
        localVariables.eflags = true;
        println("\t// INTO - interrupt on overflow, ignored");
        break;

    case x86::InsnType::Ins:
    {
        // INS - Input from port DX into ES:EDI, then adjust EDI
        // INSB (6C) = byte, INSD (6D) = dword
        localVariables.edi = true;
        localVariables.edx = true;
        localVariables.eflags = true;
        if (insn.operandSize == 1)
        {
            println("\tX86_STORE_U8(ctx.edi.u32, X86_PORT_IN_U8(ctx.edx.u16));");
            println("\tctx.edi.u32 += ctx.eflags.df ? -1 : 1;");
        }
        else if (insn.operandSize == 2)
        {
            println("\tX86_STORE_U16(ctx.edi.u32, X86_PORT_IN_U16(ctx.edx.u16));");
            println("\tctx.edi.u32 += ctx.eflags.df ? -2 : 2;");
        }
        else
        {
            println("\tX86_STORE_U32(ctx.edi.u32, X86_PORT_IN_U32(ctx.edx.u16));");
            println("\tctx.edi.u32 += ctx.eflags.df ? -4 : 4;");
        }
        break;
    }

    case x86::InsnType::Outs:
    {
        // OUTS - Output from DS:ESI to port DX, then adjust ESI
        // OUTSB (6E) = byte, OUTSD (6F) = dword
        localVariables.esi = true;
        localVariables.edx = true;
        localVariables.eflags = true;
        if (insn.operandSize == 1)
        {
            println("\tX86_PORT_OUT_U8(ctx.edx.u16, X86_LOAD_U8(ctx.esi.u32));");
            println("\tctx.esi.u32 += ctx.eflags.df ? -1 : 1;");
        }
        else if (insn.operandSize == 2)
        {
            println("\tX86_PORT_OUT_U16(ctx.edx.u16, X86_LOAD_U16(ctx.esi.u32));");
            println("\tctx.esi.u32 += ctx.eflags.df ? -2 : 2;");
        }
        else
        {
            println("\tX86_PORT_OUT_U32(ctx.edx.u16, X86_LOAD_U32(ctx.esi.u32));");
            println("\tctx.esi.u32 += ctx.eflags.df ? -4 : 4;");
        }
        break;
    }

    case x86::InsnType::Movlps:
    {
        // MOVLPS - Move low 64 bits of XMM register to/from memory
        if (insn.op[0].type == x86::OpType::Reg)
        {
            // Load: xmm.low64 = m64
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            int xmmIdx = insn.op[0].reg;
            if (xmmIdx < 8) localVariables.xmm[xmmIdx] = true;
            println("\tctx.{}.u64[0] = X86_LOAD_U64({});", GetXmmRegName(static_cast<x86::Reg>(xmmIdx)), addr);
        }
        else
        {
            // Store: m64 = xmm.low64
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            int xmmIdx = insn.op[1].reg;
            if (xmmIdx < 8) localVariables.xmm[xmmIdx] = true;
            println("\tX86_STORE_U64({}, ctx.{}.u64[0]);", addr, GetXmmRegName(static_cast<x86::Reg>(xmmIdx)));
        }
        break;
    }

    case x86::InsnType::Movhps:
    {
        // MOVHPS - Move high 64 bits of XMM register to/from memory
        if (insn.op[0].type == x86::OpType::Reg)
        {
            // Load: xmm.high64 = m64
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            int xmmIdx = insn.op[0].reg;
            if (xmmIdx < 8) localVariables.xmm[xmmIdx] = true;
            println("\tctx.{}.u64[1] = X86_LOAD_U64({});", GetXmmRegName(static_cast<x86::Reg>(xmmIdx)), addr);
        }
        else
        {
            // Store: m64 = xmm.high64
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            int xmmIdx = insn.op[1].reg;
            if (xmmIdx < 8) localVariables.xmm[xmmIdx] = true;
            println("\tX86_STORE_U64({}, ctx.{}.u64[1]);", addr, GetXmmRegName(static_cast<x86::Reg>(xmmIdx)));
        }
        break;
    }

    case x86::InsnType::Shld:
    {
        // Double precision shift left: dst = (dst << count) | (src >> (32 - count))
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], 4, localVariables);
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        std::string count = FormatOperandRead(insn.op[2], 1, localVariables);
        println("\t{{");
        println("\t\tuint8_t cnt = {} & 0x1F;", count);
        println("\t\tif (cnt) {{");
        println("\t\t\tuint32_t result = ({} << cnt) | ({} >> (32 - cnt));", dst, src);
        println("\t\t\t{};", FormatOperandWrite(insn.op[0], "result", 4, localVariables));
        println("\t\t}}");
        println("\t}}");
        break;
    }

    case x86::InsnType::Shrd:
    {
        // Double precision shift right: dst = (dst >> count) | (src << (32 - count))
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], 4, localVariables);
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        std::string count = FormatOperandRead(insn.op[2], 1, localVariables);
        println("\t{{");
        println("\t\tuint8_t cnt = {} & 0x1F;", count);
        println("\t\tif (cnt) {{");
        println("\t\t\tuint32_t result = ({} >> cnt) | ({} << (32 - cnt));", dst, src);
        println("\t\t\t{};", FormatOperandWrite(insn.op[0], "result", 4, localVariables));
        println("\t\t}}");
        println("\t}}");
        break;
    }

    case x86::InsnType::Bsf:
    {
        // Bit Scan Forward - find first set bit from LSB
        localVariables.eflags = true;
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\t{{");
        println("\t\tuint32_t val = {};", src);
        println("\t\tif (val == 0) {{");
        println("\t\t\tctx.eflags.zf = 1;");
        println("\t\t}} else {{");
        println("\t\t\tctx.eflags.zf = 0;");
        println("\t\t\tuint32_t idx = 0;");
        println("\t\t\twhile ((val & 1) == 0) {{ val >>= 1; idx++; }}");
        println("\t\t\t{};", FormatOperandWrite(insn.op[0], "idx", 4, localVariables));
        println("\t\t}}");
        println("\t}}");
        break;
    }

    case x86::InsnType::Bsr:
    {
        // Bit Scan Reverse - find first set bit from MSB
        localVariables.eflags = true;
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\t{{");
        println("\t\tuint32_t val = {};", src);
        println("\t\tif (val == 0) {{");
        println("\t\t\tctx.eflags.zf = 1;");
        println("\t\t}} else {{");
        println("\t\t\tctx.eflags.zf = 0;");
        println("\t\t\tuint32_t idx = 31;");
        println("\t\t\twhile ((val & 0x80000000) == 0) {{ val <<= 1; idx--; }}");
        println("\t\t\t{};", FormatOperandWrite(insn.op[0], "idx", 4, localVariables));
        println("\t\t}}");
        println("\t}}");
        break;
    }

    case x86::InsnType::Rdtsc:
        // Read Time Stamp Counter into EDX:EAX
        localVariables.eax = true;
        localVariables.edx = true;
        println("\t{{");
        println("\t\tuint64_t tsc = __rdtsc();");
        println("\t\tctx.eax.u32 = static_cast<uint32_t>(tsc);");
        println("\t\tctx.edx.u32 = static_cast<uint32_t>(tsc >> 32);");
        println("\t}}");
        break;

    case x86::InsnType::Xlat:
        // AL = [EBX + AL] - table lookup
        localVariables.eax = true;
        localVariables.ebx = true;
        println("\tctx.eax.u8 = X86_LOAD_U8(ctx.ebx.u32 + ctx.eax.u8);");
        break;

    case x86::InsnType::Iret:
        // Interrupt return - in user mode, treat as return
        println("\t// IRET - treating as return");
        println("\treturn;");
        break;

    case x86::InsnType::Callf:
        // Far call - Xbox uses flat 32-bit mode, far calls indicate data misinterpreted as code
        println("\t// Far call detected - likely data, not code (Xbox uses flat memory model)");
        break;

    case x86::InsnType::Movmskps:
    {
        // Extract sign bits from packed floats
        int xmmIdx = insn.op[1].reg;
        if (xmmIdx < 8) localVariables.xmm[xmmIdx] = true;
        println("\t{};", FormatOperandWrite(insn.op[0], 
            fmt::format("simde_mm_movemask_ps(ctx.{}.m128)", GetXmmRegName(static_cast<x86::Reg>(xmmIdx))), 4, localVariables));
        break;
    }

    case x86::InsnType::Cmpps:
    {
        // Compare packed single-precision floats
        auto dst = FormatXmmOperandRead(insn.op[0], localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        int pred = insn.op[2].imm & 7;
        const char* cmpOps[] = { "simde_mm_cmpeq_ps", "simde_mm_cmplt_ps", "simde_mm_cmple_ps", 
                                  "simde_mm_cmpunord_ps", "simde_mm_cmpneq_ps", "simde_mm_cmpnlt_ps",
                                  "simde_mm_cmpnle_ps", "simde_mm_cmpord_ps" };
        println("\t{};", FormatXmmOperandWrite(insn.op[0], fmt::format("{}({}, {})", cmpOps[pred], dst, src), localVariables));
        break;
    }

    case x86::InsnType::Shl:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string count = FormatOperandRead(insn.op[1], 1, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_shl<uint32_t>({}, {}, ctx.eflags)", dst, count), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Shr:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string count = FormatOperandRead(insn.op[1], 1, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_shr<uint32_t>({}, {}, ctx.eflags)", dst, count), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Sar:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string count = FormatOperandRead(insn.op[1], 1, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_sar<int32_t>({}, {}, ctx.eflags)", dst, count), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Rol:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string count = FormatOperandRead(insn.op[1], 1, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_rol<uint32_t>({}, {}, ctx.eflags)", dst, count), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Ror:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string count = FormatOperandRead(insn.op[1], 1, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_ror<uint32_t>({}, {}, ctx.eflags)", dst, count), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Rcl:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string count = FormatOperandRead(insn.op[1], 1, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_rcl<uint32_t>({}, {}, ctx.eflags)", dst, count), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Rcr:
    {
        localVariables.eflags = true;
        std::string dst = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string count = FormatOperandRead(insn.op[1], 1, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0],
            fmt::format("x86_rcr<uint32_t>({}, {}, ctx.eflags)", dst, count), insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Lea:
    {
        // LEA doesn't access memory, just calculates address
        std::string addr;
        auto& op = insn.op[1];
        
        if (op.base != x86::X86_REG_NONE)
        {
            switch (op.base)
            {
            case x86::EAX: localVariables.eax = true; break;
            case x86::ECX: localVariables.ecx = true; break;
            case x86::EDX: localVariables.edx = true; break;
            case x86::EBX: localVariables.ebx = true; break;
            case x86::ESP: localVariables.esp = true; break;
            case x86::EBP: localVariables.ebp = true; break;
            case x86::ESI: localVariables.esi = true; break;
            case x86::EDI: localVariables.edi = true; break;
            }
            addr = fmt::format("ctx.{}.u32", GetRegName32(op.base));
        }
        
        if (op.index != x86::X86_REG_NONE)
        {
            switch (op.index)
            {
            case x86::EAX: localVariables.eax = true; break;
            case x86::ECX: localVariables.ecx = true; break;
            case x86::EDX: localVariables.edx = true; break;
            case x86::EBX: localVariables.ebx = true; break;
            case x86::ESI: localVariables.esi = true; break;
            case x86::EDI: localVariables.edi = true; break;
            }
            
            std::string indexPart = fmt::format("ctx.{}.u32", GetRegName32(op.index));
            if (op.scale > 1)
                indexPart = fmt::format("({} * {})", indexPart, op.scale);
            
            if (addr.empty())
                addr = indexPart;
            else
                addr = fmt::format("({} + {})", addr, indexPart);
        }
        
        if (op.disp != 0 || addr.empty())
        {
            if (addr.empty())
                addr = fmt::format("0x{:X}u", static_cast<uint32_t>(op.disp));
            else if (op.disp > 0)
                addr = fmt::format("({} + 0x{:X}u)", addr, op.disp);
            else
                addr = fmt::format("({} - 0x{:X}u)", addr, -op.disp);
        }
        
        println("\t{};", FormatOperandWrite(insn.op[0], addr, 4, localVariables));
        break;
    }

    case x86::InsnType::Movzx:
    {
        // Zero-extend move
        int srcSize = (insn.length >= 4 && data[insn.length-3] == 0xB7) ? 2 : 1; // 0x0F B7 = movzx r32, r/m16
        std::string src = FormatOperandRead(insn.op[1], srcSize, localVariables);
        println("\t{};", FormatOperandWrite(insn.op[0], src, 4, localVariables));
        break;
    }

    case x86::InsnType::Movsx:
    {
        // Sign-extend move
        int srcSize = (insn.length >= 4 && data[insn.length-3] == 0xBF) ? 2 : 1; // 0x0F BF = movsx r32, r/m16
        std::string src = FormatOperandRead(insn.op[1], srcSize, localVariables);
        std::string cast = srcSize == 2 ? "static_cast<int32_t>(static_cast<int16_t>({}))" : "static_cast<int32_t>(static_cast<int8_t>({}))";
        println("\t{};", FormatOperandWrite(insn.op[0], fmt::format(cast, src), 4, localVariables));
        break;
    }

    case x86::InsnType::Xchg:
    {
        localVariables.temp = true;
        std::string op1 = FormatOperandRead(insn.op[0], insn.operandSize, localVariables);
        std::string op2 = FormatOperandRead(insn.op[1], insn.operandSize, localVariables);
        println("\ttemp = {};", op1);
        println("\t{};", FormatOperandWrite(insn.op[0], op2, insn.operandSize, localVariables));
        println("\t{};", FormatOperandWrite(insn.op[1], "temp", insn.operandSize, localVariables));
        break;
    }

    case x86::InsnType::Movs:
    case x86::InsnType::Stos:
    case x86::InsnType::Lods:
    case x86::InsnType::Scas:
    case x86::InsnType::Cmps:
    {
        // String operations - handle REP prefix if present
        const char* funcName = nullptr;
        switch (insn.type)
        {
        case x86::InsnType::Movs: funcName = insn.operandSize == 4 ? "x86_movsd" : (insn.operandSize == 2 ? "x86_movsw" : "x86_movsb"); break;
        case x86::InsnType::Stos: funcName = insn.operandSize == 4 ? "x86_stosd" : (insn.operandSize == 2 ? "x86_stosw" : "x86_stosb"); break;
        case x86::InsnType::Lods: funcName = insn.operandSize == 4 ? "x86_lodsd" : (insn.operandSize == 2 ? "x86_lodsw" : "x86_lodsb"); break;
        case x86::InsnType::Scas: funcName = insn.operandSize == 4 ? "x86_scasd" : (insn.operandSize == 2 ? "x86_scasw" : "x86_scasb"); break;
        case x86::InsnType::Cmps: funcName = insn.operandSize == 4 ? "x86_cmpsd" : (insn.operandSize == 2 ? "x86_cmpsw" : "x86_cmpsb"); break;
        }
        
        localVariables.esi = true;
        localVariables.edi = true;
        localVariables.eax = true;
        localVariables.ecx = true;
        localVariables.eflags = true;
        
        if (insn.hasRepPrefix)
        {
            println("\twhile (ctx.ecx.u32 > 0) {{");
            println("\t\t{}(ctx, base);", funcName);
            println("\t\tctx.ecx.u32--;");
            println("\t}}");
        }
        else
        {
            println("\t{}(ctx, base);", funcName);
        }
        break;
    }

    case x86::InsnType::Cmp:
    {
        localVariables.eflags = true;
        std::string left = FormatOperandRead(insn.op[0], 4, localVariables);
        std::string right = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\tctx.eflags.compare<int32_t>({}, {});", left, right);
        break;
    }

    case x86::InsnType::Test:
    {
        localVariables.eflags = true;
        std::string left = FormatOperandRead(insn.op[0], 4, localVariables);
        std::string right = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\tctx.eflags.test<int32_t>({} & {});", left, right);
        break;
    }

    case x86::InsnType::Jmp:
        if (insn.is_branch_relative)
        {
            // Check if target is in a function chunk
            bool isInChunk = false;
            auto chunksIt = config.functionChunks.find(fn.base);
            if (chunksIt != config.functionChunks.end())
            {
                for (const auto& [chunkAddr, chunkSize] : chunksIt->second)
                {
                    if (insn.branch_target >= chunkAddr && insn.branch_target < chunkAddr + chunkSize)
                    {
                        isInChunk = true;
                        break;
                    }
                }
            }
            
            // Check if target is outside effective function range OR is another function's entry (tail call)
            bool isTailCall = (insn.branch_target < effectiveBase || insn.branch_target >= effectiveEnd) && !isInChunk;
            if (!isTailCall && functionEntryPoints.count(insn.branch_target) && insn.branch_target != fn.base && !isInChunk)
            {
                // Target is within "function range" but is actually another function - tail call
                isTailCall = true;
            }
            
            if (isTailCall)
            {
                // Tail call
                printFunctionCall(insn.branch_target);
                println("\treturn;");
            }
            else
            {
                println("\tgoto loc_{:X};", insn.branch_target);
            }
        }
        else if (insn.op[0].type == x86::OpType::Reg)
        {
            // Indirect jump through register
            println("\tX86_CALL_INDIRECT_FUNC({});", FormatOperandRead(insn.op[0], 4, localVariables));
            println("\treturn;");
        }
        else
        {
            // Memory indirect jump - could be jump table
            println("\tX86_CALL_INDIRECT_FUNC({});", FormatOperandRead(insn.op[0], 4, localVariables));
            println("\treturn;");
        }
        break;

    case x86::InsnType::JmpIndirect:
        if (switchTable != config.switchTables.end())
        {
            // This is a switch table jump - switch on the index register, not the loaded value
            auto indexReg = static_cast<x86::Reg>(switchTable->second.reg);
            println("\tswitch (ctx.{}.u32) {{", GetRegName32(indexReg));
            for (size_t i = 0; i < switchTable->second.labels.size(); i++)
            {
                auto label = switchTable->second.labels[i];
                if (label < effectiveBase || label >= effectiveEnd)
                {
                    println("\tcase {}:", i);
                    println("\t\t// ERROR: Switch case {:X} jumps outside function", label);
                    println("\t\treturn;");
                }
                else
                {
                    println("\tcase {}:", i);
                    println("\t\tgoto loc_{:X};", label);
                }
            }
            println("\tdefault:");
            println("\t\t__builtin_unreachable();");
            println("\t}}");
            switchTable = config.switchTables.end();
        }
        else
        {
            // Unknown indirect jump
            println("\tX86_CALL_INDIRECT_FUNC({});", FormatOperandRead(insn.op[0], 4, localVariables));
            println("\treturn;");
        }
        break;

    case x86::InsnType::Jcc:
        printConditionalJump(getConditionString(insn.cond).c_str(), insn.branch_target);
        break;

    case x86::InsnType::Call:
        if (insn.is_branch_relative)
        {
            printFunctionCall(insn.branch_target);
        }
        else
        {
            // Indirect call
            println("\tX86_CALL_INDIRECT_FUNC({});", FormatOperandRead(insn.op[0], 4, localVariables));
        }
        break;

    case x86::InsnType::Ret:
        if (insn.op[0].type == x86::OpType::Imm && insn.op[0].imm > 0)
        {
            // ret imm16 - clean up stack
            localVariables.esp = true;
            println("\tctx.esp.u32 += {};", insn.op[0].imm);
        }
        println("\treturn;");
        break;

    case x86::InsnType::Leave:
        localVariables.esp = true;
        localVariables.ebp = true;
        println("\tctx.esp.u32 = ctx.ebp.u32;");
        println("\tctx.ebp.u32 = X86_LOAD_U32(ctx.esp.u32);");
        println("\tctx.esp.u32 += 4;");
        break;

    case x86::InsnType::Nop:
    case x86::InsnType::Int3:
        // No operation
        break;

    case x86::InsnType::Int:
        // Software interrupt - stub for recompilation
        println("\t// INT 0x{:02X} - software interrupt", static_cast<int>(insn.op[0].imm));
        break;

    case x86::InsnType::SetCC:
    {
        // SETcc - set byte on condition
        localVariables.eflags = true;
        std::string condExpr = getConditionString(insn.cond);
        println("\t{};", FormatOperandWrite(insn.op[0], fmt::format("({}) ? 1u : 0u", condExpr), 1, localVariables));
        break;
    }

    case x86::InsnType::Cmovcc:
    {
        // CMOVcc - conditional move
        localVariables.eflags = true;
        std::string condExpr = getConditionString(insn.cond);
        std::string dst = FormatOperandRead(insn.op[0], 4, localVariables);
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\tif ({}) {};", condExpr, FormatOperandWrite(insn.op[0], src, 4, localVariables));
        break;
    }

    // ==================== SSE Move Instructions ====================
    
    case x86::InsnType::Movss:
        // Move scalar single-precision float
        if (insn.op[0].type == x86::OpType::Reg && insn.op[1].type == x86::OpType::Reg)
        {
            // XMM to XMM: only moves lower 32 bits, preserves upper bits of dest
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            localVariables.xmm[insn.op[0].reg] = true;
            println("\tctx.{}.f32[0] = simde_mm_cvtss_f32({});", GetXmmRegName(insn.op[0].reg), src);
        }
        else if (insn.op[0].type == x86::OpType::Reg)
        {
            // Memory to XMM: loads 32 bits, zeros upper bits
            auto addr = FormatOperand(insn.op[1], 4, localVariables);
            localVariables.xmm[insn.op[0].reg] = true;
            println("\tctx.{}.m128 = X86_LOAD_XMM_SS({});", GetXmmRegName(insn.op[0].reg), addr);
        }
        else
        {
            // XMM to Memory: stores lower 32 bits
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            auto addr = FormatOperand(insn.op[0], 4, localVariables);
            println("\tX86_STORE_XMM_SS({}, {});", addr, src);
        }
        break;
        
    case x86::InsnType::Movsd_sse:
        // Move scalar double-precision float
        if (insn.op[0].type == x86::OpType::Reg && insn.op[1].type == x86::OpType::Reg)
        {
            // XMM to XMM: only moves lower 64 bits, preserves upper bits of dest
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            localVariables.xmm[insn.op[0].reg] = true;
            println("\tctx.{}.f64[0] = simde_mm_cvtsd_f64({});", GetXmmRegName(insn.op[0].reg), src);
        }
        else if (insn.op[0].type == x86::OpType::Reg)
        {
            // Memory to XMM: loads 64 bits, zeros upper bits
            auto addr = FormatOperand(insn.op[1], 4, localVariables);
            localVariables.xmm[insn.op[0].reg] = true;
            println("\tctx.{}.m128d = X86_LOAD_XMM_SD({});", GetXmmRegName(insn.op[0].reg), addr);
        }
        else
        {
            // XMM to Memory: stores lower 64 bits
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            auto addr = FormatOperand(insn.op[0], 4, localVariables);
            println("\tX86_STORE_XMM_SD({}, simde_mm_castps_pd({}));", addr, src);
        }
        break;

    case x86::InsnType::Movaps:
    case x86::InsnType::Movups:
        // Move aligned/unaligned packed single-precision
        if (insn.op[0].type == x86::OpType::Reg)
        {
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            localVariables.xmm[insn.op[0].reg] = true;
            println("\tctx.{}.m128 = {};", GetXmmRegName(insn.op[0].reg), src);
        }
        else
        {
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            auto addr = FormatOperand(insn.op[0], 4, localVariables);
            println("\tX86_STORE_XMM({}, {});", addr, src);
        }
        break;

    case x86::InsnType::Movapd:
    case x86::InsnType::Movupd:
        // Move aligned/unaligned packed double-precision
        if (insn.op[0].type == x86::OpType::Reg)
        {
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            localVariables.xmm[insn.op[0].reg] = true;
            println("\tctx.{}.m128 = {};", GetXmmRegName(insn.op[0].reg), src);
        }
        else
        {
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            auto addr = FormatOperand(insn.op[0], 4, localVariables);
            println("\tX86_STORE_XMM({}, {});", addr, src);
        }
        break;

    // ==================== SSE Scalar Arithmetic ====================

    case x86::InsnType::Addss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_add_ss(ctx.{}.m128, {});", dst, dst, src);
        break;
    }
    
    case x86::InsnType::Addsd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_add_sd(ctx.{}.m128d, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    case x86::InsnType::Subss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_sub_ss(ctx.{}.m128, {});", dst, dst, src);
        break;
    }
    
    case x86::InsnType::Subsd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_sub_sd(ctx.{}.m128d, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    case x86::InsnType::Mulss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_mul_ss(ctx.{}.m128, {});", dst, dst, src);
        break;
    }
    
    case x86::InsnType::Mulsd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_mul_sd(ctx.{}.m128d, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    case x86::InsnType::Divss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_div_ss(ctx.{}.m128, {});", dst, dst, src);
        break;
    }
    
    case x86::InsnType::Divsd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_div_sd(ctx.{}.m128d, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    case x86::InsnType::Sqrtss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_sqrt_ss({});", dst, src);
        break;
    }
    
    case x86::InsnType::Sqrtsd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_sqrt_sd(ctx.{}.m128d, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    case x86::InsnType::Rsqrtss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_rsqrt_ss({});", dst, src);
        break;
    }

    case x86::InsnType::Rsqrtps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_rsqrt_ps({});", dst, src);
        break;
    }

    case x86::InsnType::Rcpss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_rcp_ss({});", dst, src);
        break;
    }

    case x86::InsnType::Rcpps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_rcp_ps({});", dst, src);
        break;
    }

    case x86::InsnType::Minss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_min_ss(ctx.{}.m128, {});", dst, dst, src);
        break;
    }
    
    case x86::InsnType::Minsd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_min_sd(ctx.{}.m128d, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    case x86::InsnType::Maxss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_max_ss(ctx.{}.m128, {});", dst, dst, src);
        break;
    }
    
    case x86::InsnType::Maxsd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_max_sd(ctx.{}.m128d, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    // ==================== SSE Packed Arithmetic ====================

    case x86::InsnType::Addps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_add_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Subps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_sub_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Mulps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_mul_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Divps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_div_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Sqrtps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_sqrt_ps({});", dst, src);
        break;
    }

    case x86::InsnType::Minps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_min_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Maxps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_max_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    // ==================== SSE Logical Operations ====================

    case x86::InsnType::Andps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_and_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Andnps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_andnot_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Orps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_or_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Xorps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_xor_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    // ==================== SSE Shuffle/Unpack Operations ====================

    case x86::InsnType::Shufps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        // op[2] contains the immediate shuffle control byte
        println("\tctx.{}.m128 = simde_mm_shuffle_ps(ctx.{}.m128, {}, 0x{:02X});", 
                dst, dst, src, static_cast<uint8_t>(insn.op[2].imm));
        break;
    }

    case x86::InsnType::Unpcklps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_unpacklo_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Unpckhps:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128 = simde_mm_unpackhi_ps(ctx.{}.m128, {});", dst, dst, src);
        break;
    }

    // ==================== SSE Comparison Operations ====================

    case x86::InsnType::Cmpss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        // op[2] contains the immediate comparison predicate
        println("\tctx.{}.m128 = simde_mm_cmp_ss(ctx.{}.m128, {}, {});", 
                dst, dst, src, static_cast<int>(insn.op[2].imm));
        break;
    }

    case x86::InsnType::Cmpsd_sse:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        println("\tctx.{}.m128d = simde_mm_cmp_sd(ctx.{}.m128d, simde_mm_castps_pd({}), {});", 
                dst, dst, src, static_cast<int>(insn.op[2].imm));
        break;
    }

    case x86::InsnType::Comiss:
    {
        auto dst = FormatXmmOperandRead(insn.op[0], localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.eflags = true;
        println("\t{{");
        println("\t\tfloat a = simde_mm_cvtss_f32({});", dst);
        println("\t\tfloat b = simde_mm_cvtss_f32({});", src);
        println("\t\tctx.eflags.zf = (a == b);");
        println("\t\tctx.eflags.pf = (__builtin_isnan(a) || __builtin_isnan(b));");
        println("\t\tctx.eflags.cf = (a < b);");
        println("\t\tctx.eflags.of = 0;");
        println("\t\tctx.eflags.sf = 0;");
        println("\t\tctx.eflags.af = 0;");
        println("\t}}");
        break;
    }

    case x86::InsnType::Comisd:
    {
        auto dst = FormatXmmOperandRead(insn.op[0], localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.eflags = true;
        println("\t{{");
        println("\t\tdouble a = simde_mm_cvtsd_f64(simde_mm_castps_pd({}));", dst);
        println("\t\tdouble b = simde_mm_cvtsd_f64(simde_mm_castps_pd({}));", src);
        println("\t\tctx.eflags.zf = (a == b);");
        println("\t\tctx.eflags.pf = (__builtin_isnan(a) || __builtin_isnan(b));");
        println("\t\tctx.eflags.cf = (a < b);");
        println("\t\tctx.eflags.of = 0;");
        println("\t\tctx.eflags.sf = 0;");
        println("\t\tctx.eflags.af = 0;");
        println("\t}}");
        break;
    }

    case x86::InsnType::Ucomiss:
    {
        auto dst = FormatXmmOperandRead(insn.op[0], localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.eflags = true;
        println("\t{{");
        println("\t\tfloat a = simde_mm_cvtss_f32({});", dst);
        println("\t\tfloat b = simde_mm_cvtss_f32({});", src);
        println("\t\tctx.eflags.zf = (a == b);");
        println("\t\tctx.eflags.pf = (__builtin_isnan(a) || __builtin_isnan(b));");
        println("\t\tctx.eflags.cf = (a < b);");
        println("\t\tctx.eflags.of = 0;");
        println("\t\tctx.eflags.sf = 0;");
        println("\t\tctx.eflags.af = 0;");
        println("\t}}");
        break;
    }

    case x86::InsnType::Ucomisd:
    {
        auto dst = FormatXmmOperandRead(insn.op[0], localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.eflags = true;
        println("\t{{");
        println("\t\tdouble a = simde_mm_cvtsd_f64(simde_mm_castps_pd({}));", dst);
        println("\t\tdouble b = simde_mm_cvtsd_f64(simde_mm_castps_pd({}));", src);
        println("\t\tctx.eflags.zf = (a == b);");
        println("\t\tctx.eflags.pf = (__builtin_isnan(a) || __builtin_isnan(b));");
        println("\t\tctx.eflags.cf = (a < b);");
        println("\t\tctx.eflags.of = 0;");
        println("\t\tctx.eflags.sf = 0;");
        println("\t\tctx.eflags.af = 0;");
        println("\t}}");
        break;
    }

    // ==================== SSE Conversion Operations ====================

    case x86::InsnType::Cvtss2sd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        // Convert single to double, result in low 64 bits
        println("\tctx.{}.m128d = simde_mm_cvtss_sd(ctx.{}.m128d, {});", dst, dst, src);
        break;
    }

    case x86::InsnType::Cvtsd2ss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        // Convert double to single, result in low 32 bits
        println("\tctx.{}.m128 = simde_mm_cvtsd_ss(ctx.{}.m128, simde_mm_castps_pd({}));", dst, dst, src);
        break;
    }

    case x86::InsnType::Cvtsi2ss:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatOperandRead(insn.op[1], 4, localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        // Convert signed int32 to single float
        println("\tctx.{}.m128 = simde_mm_cvtsi32_ss(ctx.{}.m128, (int32_t){});", dst, dst, src);
        break;
    }

    case x86::InsnType::Cvtsi2sd:
    {
        auto dst = GetXmmRegName(insn.op[0].reg);
        auto src = FormatOperandRead(insn.op[1], 4, localVariables);
        localVariables.xmm[insn.op[0].reg] = true;
        // Convert signed int32 to double float
        println("\tctx.{}.m128d = simde_mm_cvtsi32_sd(ctx.{}.m128d, (int32_t){});", dst, dst, src);
        break;
    }

    case x86::InsnType::Cvtss2si:
    {
        auto dst = FormatOperandWrite(insn.op[0], "tmp", 4, localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.temp = true;
        // Convert single float to signed int32 (rounded)
        println("\t{{");
        println("\t\tint32_t tmp = simde_mm_cvtss_si32({});", src);
        println("\t\t{};", dst);
        println("\t}}");
        break;
    }

    case x86::InsnType::Cvtsd2si:
    {
        auto dst = FormatOperandWrite(insn.op[0], "tmp", 4, localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.temp = true;
        // Convert double float to signed int32 (rounded)
        println("\t{{");
        println("\t\tint32_t tmp = simde_mm_cvtsd_si32(simde_mm_castps_pd({}));", src);
        println("\t\t{};", dst);
        println("\t}}");
        break;
    }

    case x86::InsnType::Cvttss2si:
    {
        auto dst = FormatOperandWrite(insn.op[0], "tmp", 4, localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.temp = true;
        // Convert single float to signed int32 (truncated)
        println("\t{{");
        println("\t\tint32_t tmp = simde_mm_cvttss_si32({});", src);
        println("\t\t{};", dst);
        println("\t}}");
        break;
    }

    case x86::InsnType::Cvttsd2si:
    {
        auto dst = FormatOperandWrite(insn.op[0], "tmp", 4, localVariables);
        auto src = FormatXmmOperandRead(insn.op[1], localVariables);
        localVariables.temp = true;
        // Convert double float to signed int32 (truncated)
        println("\t{{");
        println("\t\tint32_t tmp = simde_mm_cvttsd_si32(simde_mm_castps_pd({}));", src);
        println("\t\t{};", dst);
        println("\t}}");
        break;
    }

    // ==================== FPU Instructions ====================
    
    case x86::InsnType::Fld:
    {
        // FLD - Load floating point value onto FPU stack
        localVariables.fpu = true;
        uint8_t modrm = insn.fpuModrm;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            // Register form - FLD ST(i) or FLD constant
            if (modrm >= 0xC0 && modrm <= 0xC7)
            {
                // FLD ST(i) - push ST(i) onto stack
                int srcIdx = modrm & 7;
                println("\tctx.fpu.push(ctx.fpu.ST({}).f80);", srcIdx);
            }
            else switch (modrm)
            {
            case 0xE8: println("\tctx.fpu.push(1.0L);"); break;                          // FLD1
            case 0xE9: println("\tctx.fpu.push(3.32192809488736234787L);"); break;       // FLDL2T (log2(10))
            case 0xEA: println("\tctx.fpu.push(1.44269504088896340736L);"); break;       // FLDL2E (log2(e))
            case 0xEB: println("\tctx.fpu.push(3.14159265358979323846L);"); break;       // FLDPI
            case 0xEC: println("\tctx.fpu.push(0.30102999566398119521L);"); break;       // FLDLG2 (log10(2))
            case 0xED: println("\tctx.fpu.push(0.69314718055994530942L);"); break;       // FLDLN2 (ln(2))
            case 0xEE: println("\tctx.fpu.push(0.0L);"); break;                          // FLDZ
            default:
                println("\t// Unhandled FLD register form: modrm=0x{:02X}", modrm);
                break;
            }
        }
        else
        {
            // Memory form - load from memory
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            if (insn.fpuInteger)
            {
                // FILD - load integer
                switch (insn.operandSize)
                {
                case 2: println("\tctx.fpu.push(static_cast<long double>(static_cast<int16_t>(X86_LOAD_U16({}))));", addr); break;
                case 4: println("\tctx.fpu.push(static_cast<long double>(static_cast<int32_t>(X86_LOAD_U32({}))));", addr); break;
                case 8: println("\tctx.fpu.push(static_cast<long double>(static_cast<int64_t>(X86_LOAD_U64({}))));", addr); break;
                default: println("\t// Unknown FILD operand size: {}", insn.operandSize); break;
                }
            }
            else
            {
                // FLD - load float
                switch (insn.operandSize)
                {
                case 4: println("\tctx.fpu.push(static_cast<long double>(X86_LOAD_F32({})));", addr); break;
                case 8: println("\tctx.fpu.push(static_cast<long double>(X86_LOAD_F64({})));", addr); break;
                case 10: println("\tctx.fpu.push(X86_LOAD_F80({}));", addr); break;  // Extended precision
                default: println("\t// Unknown FLD operand size: {}", insn.operandSize); break;
                }
            }
        }
        break;
    }
    
    case x86::InsnType::Fild:
    {
        // FILD - Load integer onto FPU stack
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        switch (insn.operandSize)
        {
        case 2: println("\tctx.fpu.push(static_cast<long double>(static_cast<int16_t>(X86_LOAD_U16({}))));", addr); break;
        case 4: println("\tctx.fpu.push(static_cast<long double>(static_cast<int32_t>(X86_LOAD_U32({}))));", addr); break;
        case 8: println("\tctx.fpu.push(static_cast<long double>(static_cast<int64_t>(X86_LOAD_U64({}))));", addr); break;
        default: println("\t// Unknown FILD operand size: {}", insn.operandSize); break;
        }
        break;
    }
    
    case x86::InsnType::Fst:
    {
        // FST/FSTP - Store floating point value
        localVariables.fpu = true;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            // FST/FSTP ST(i) - copy ST(0) to ST(i)
            int dstIdx = insn.fpuModrm & 7;
            println("\tctx.fpu.ST({}).f80 = ctx.fpu.ST(0).f80;", dstIdx);
        }
        else
        {
            // Memory form - store to memory
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            switch (insn.operandSize)
            {
            case 4: println("\tX86_STORE_F32({}, static_cast<float>(ctx.fpu.ST(0).f80));", addr); break;
            case 8: println("\tX86_STORE_F64({}, static_cast<double>(ctx.fpu.ST(0).f80));", addr); break;
            case 10: println("\tX86_STORE_F80({}, ctx.fpu.ST(0).f80);", addr); break;
            default: println("\t// Unknown FST operand size: {}", insn.operandSize); break;
            }
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
        }
        break;
    }
    
    case x86::InsnType::Fist:
    {
        // FIST/FISTP - Store integer
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        switch (insn.operandSize)
        {
        case 2: println("\tX86_STORE_U16({}, static_cast<int16_t>(ctx.fpu.ST(0).f80));", addr); break;
        case 4: println("\tX86_STORE_U32({}, static_cast<int32_t>(ctx.fpu.ST(0).f80));", addr); break;
        case 8: println("\tX86_STORE_U64({}, static_cast<int64_t>(ctx.fpu.ST(0).f80));", addr); break;
        default: println("\t// Unknown FIST operand size: {}", insn.operandSize); break;
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
        }
        break;
    }
    
    case x86::InsnType::Fadd:
    {
        // FADD/FADDP - Floating point add
        localVariables.fpu = true;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            // Register form
            int idx = insn.fpuModrm & 7;
            uint8_t opcode = insn.fpuOpcode;
            
            if (opcode == 0xD8)
            {
                // FADD ST(0), ST(i) - result in ST(0)
                println("\tctx.fpu.ST(0).f80 += ctx.fpu.ST({}).f80;", idx);
            }
            else // 0xDC or 0xDE
            {
                // FADD ST(i), ST(0) - result in ST(i)
                println("\tctx.fpu.ST({}).f80 += ctx.fpu.ST(0).f80;", idx);
            }
        }
        else
        {
            // Memory form - add memory operand to ST(0)
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            if (insn.fpuInteger)
            {
                switch (insn.operandSize)
                {
                case 2: println("\tctx.fpu.ST(0).f80 += static_cast<long double>(static_cast<int16_t>(X86_LOAD_U16({})));", addr); break;
                case 4: println("\tctx.fpu.ST(0).f80 += static_cast<long double>(static_cast<int32_t>(X86_LOAD_U32({})));", addr); break;
                default: println("\t// Unknown FIADD operand size"); break;
                }
            }
            else
            {
                switch (insn.operandSize)
                {
                case 4: println("\tctx.fpu.ST(0).f80 += static_cast<long double>(X86_LOAD_F32({}));", addr); break;
                case 8: println("\tctx.fpu.ST(0).f80 += static_cast<long double>(X86_LOAD_F64({}));", addr); break;
                default: println("\t// Unknown FADD operand size"); break;
                }
            }
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
        }
        break;
    }
    
    case x86::InsnType::Fsub:
    {
        // FSUB/FSUBP/FSUBR/FSUBRP - Floating point subtract
        localVariables.fpu = true;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            // Register form
            int idx = insn.fpuModrm & 7;
            uint8_t opcode = insn.fpuOpcode;
            
            if (opcode == 0xD8)
            {
                // Result in ST(0)
                if (insn.fpuReverse)
                    println("\tctx.fpu.ST(0).f80 = ctx.fpu.ST({}).f80 - ctx.fpu.ST(0).f80;", idx);
                else
                    println("\tctx.fpu.ST(0).f80 -= ctx.fpu.ST({}).f80;", idx);
            }
            else // 0xDC or 0xDE
            {
                // Result in ST(i)
                if (insn.fpuReverse)
                    println("\tctx.fpu.ST({0}).f80 = ctx.fpu.ST(0).f80 - ctx.fpu.ST({0}).f80;", idx);
                else
                    println("\tctx.fpu.ST({}).f80 -= ctx.fpu.ST(0).f80;", idx);
            }
        }
        else
        {
            // Memory form
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            std::string memVal;
            if (insn.fpuInteger)
            {
                switch (insn.operandSize)
                {
                case 2: memVal = fmt::format("static_cast<long double>(static_cast<int16_t>(X86_LOAD_U16({})))", addr); break;
                case 4: memVal = fmt::format("static_cast<long double>(static_cast<int32_t>(X86_LOAD_U32({})))", addr); break;
                default: println("\t// Unknown FISUB operand size"); break;
                }
            }
            else
            {
                switch (insn.operandSize)
                {
                case 4: memVal = fmt::format("static_cast<long double>(X86_LOAD_F32({}))", addr); break;
                case 8: memVal = fmt::format("static_cast<long double>(X86_LOAD_F64({}))", addr); break;
                default: println("\t// Unknown FSUB operand size"); break;
                }
            }
            if (!memVal.empty())
            {
                if (insn.fpuReverse)
                    println("\tctx.fpu.ST(0).f80 = {} - ctx.fpu.ST(0).f80;", memVal);
                else
                    println("\tctx.fpu.ST(0).f80 -= {};", memVal);
            }
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
        }
        break;
    }
    
    case x86::InsnType::Fmul:
    {
        // FMUL/FMULP - Floating point multiply
        localVariables.fpu = true;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            int idx = insn.fpuModrm & 7;
            uint8_t opcode = insn.fpuOpcode;
            
            if (opcode == 0xD8)
                println("\tctx.fpu.ST(0).f80 *= ctx.fpu.ST({}).f80;", idx);
            else
                println("\tctx.fpu.ST({}).f80 *= ctx.fpu.ST(0).f80;", idx);
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            if (insn.fpuInteger)
            {
                switch (insn.operandSize)
                {
                case 2: println("\tctx.fpu.ST(0).f80 *= static_cast<long double>(static_cast<int16_t>(X86_LOAD_U16({})));", addr); break;
                case 4: println("\tctx.fpu.ST(0).f80 *= static_cast<long double>(static_cast<int32_t>(X86_LOAD_U32({})));", addr); break;
                default: println("\t// Unknown FIMUL operand size"); break;
                }
            }
            else
            {
                switch (insn.operandSize)
                {
                case 4: println("\tctx.fpu.ST(0).f80 *= static_cast<long double>(X86_LOAD_F32({}));", addr); break;
                case 8: println("\tctx.fpu.ST(0).f80 *= static_cast<long double>(X86_LOAD_F64({}));", addr); break;
                default: println("\t// Unknown FMUL operand size"); break;
                }
            }
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
        }
        break;
    }
    
    case x86::InsnType::Fdiv:
    {
        // FDIV/FDIVP/FDIVR/FDIVRP - Floating point divide
        localVariables.fpu = true;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            int idx = insn.fpuModrm & 7;
            uint8_t opcode = insn.fpuOpcode;
            
            if (opcode == 0xD8)
            {
                if (insn.fpuReverse)
                    println("\tctx.fpu.ST(0).f80 = ctx.fpu.ST({}).f80 / ctx.fpu.ST(0).f80;", idx);
                else
                    println("\tctx.fpu.ST(0).f80 /= ctx.fpu.ST({}).f80;", idx);
            }
            else
            {
                if (insn.fpuReverse)
                    println("\tctx.fpu.ST({0}).f80 = ctx.fpu.ST(0).f80 / ctx.fpu.ST({0}).f80;", idx);
                else
                    println("\tctx.fpu.ST({}).f80 /= ctx.fpu.ST(0).f80;", idx);
            }
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            std::string memVal;
            if (insn.fpuInteger)
            {
                switch (insn.operandSize)
                {
                case 2: memVal = fmt::format("static_cast<long double>(static_cast<int16_t>(X86_LOAD_U16({})))", addr); break;
                case 4: memVal = fmt::format("static_cast<long double>(static_cast<int32_t>(X86_LOAD_U32({})))", addr); break;
                default: println("\t// Unknown FIDIV operand size"); break;
                }
            }
            else
            {
                switch (insn.operandSize)
                {
                case 4: memVal = fmt::format("static_cast<long double>(X86_LOAD_F32({}))", addr); break;
                case 8: memVal = fmt::format("static_cast<long double>(X86_LOAD_F64({}))", addr); break;
                default: println("\t// Unknown FDIV operand size"); break;
                }
            }
            if (!memVal.empty())
            {
                if (insn.fpuReverse)
                    println("\tctx.fpu.ST(0).f80 = {} / ctx.fpu.ST(0).f80;", memVal);
                else
                    println("\tctx.fpu.ST(0).f80 /= {};", memVal);
            }
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
        }
        break;
    }
    
    case x86::InsnType::Fcom:
    {
        // FCOM/FCOMP/FCOMPP - Compare floating point
        localVariables.fpu = true;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            int idx = insn.fpuModrm & 7;
            println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, ctx.fpu.ST({}).f80);", idx);
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            if (insn.fpuInteger)
            {
                switch (insn.operandSize)
                {
                case 2: println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, static_cast<long double>(static_cast<int16_t>(X86_LOAD_U16({}))));", addr); break;
                case 4: println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, static_cast<long double>(static_cast<int32_t>(X86_LOAD_U32({}))));", addr); break;
                default: println("\t// Unknown FICOM operand size"); break;
                }
            }
            else
            {
                switch (insn.operandSize)
                {
                case 4: println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, static_cast<long double>(X86_LOAD_F32({})));", addr); break;
                case 8: println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, static_cast<long double>(X86_LOAD_F64({})));", addr); break;
                default: println("\t// Unknown FCOM operand size"); break;
                }
            }
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
            // FCOMPP pops twice
            if (insn.fpuModrm == 0xD9 && insn.fpuOpcode == 0xDE)
            {
                println("\tctx.fpu.pop();");
            }
        }
        break;
    }
    
    case x86::InsnType::Fucom:
    {
        // FUCOM/FUCOMP/FUCOMPP - Unordered compare
        localVariables.fpu = true;
        
        if (insn.op[0].type == x86::OpType::Reg)
        {
            int idx = insn.fpuModrm & 7;
            println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, ctx.fpu.ST({}).f80);", idx);
        }
        else
        {
            println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, ctx.fpu.ST(1).f80);");
        }
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
            // FUCOMPP pops twice
            if (insn.fpuModrm == 0xE9 && insn.fpuOpcode == 0xDA)
            {
                println("\tctx.fpu.pop();");
            }
        }
        break;
    }
    
    case x86::InsnType::Fcomi:
    {
        // FCOMI/FCOMIP/FUCOMI/FUCOMIP - Compare and set EFLAGS
        localVariables.fpu = true;
        localVariables.eflags = true;
        int idx = insn.fpuModrm & 7;
        
        // These instructions set ZF, PF, CF directly (not FPU status word)
        println("\t{{");
        println("\t\tlong double a = ctx.fpu.ST(0).f80;");
        println("\t\tlong double b = ctx.fpu.ST({}).f80;", idx);
        println("\t\tif (__builtin_isnan(a) || __builtin_isnan(b)) {{");
        println("\t\t\tctx.eflags.zf = 1; ctx.eflags.pf = 1; ctx.eflags.cf = 1;");
        println("\t\t}} else if (a > b) {{");
        println("\t\t\tctx.eflags.zf = 0; ctx.eflags.pf = 0; ctx.eflags.cf = 0;");
        println("\t\t}} else if (a < b) {{");
        println("\t\t\tctx.eflags.zf = 0; ctx.eflags.pf = 0; ctx.eflags.cf = 1;");
        println("\t\t}} else {{");
        println("\t\t\tctx.eflags.zf = 1; ctx.eflags.pf = 0; ctx.eflags.cf = 0;");
        println("\t\t}}");
        println("\t}}");
        
        if (insn.fpuPop)
        {
            println("\tctx.fpu.pop();");
        }
        break;
    }
    
    case x86::InsnType::Fxch:
    {
        // FXCH - Exchange ST(0) with ST(i)
        localVariables.fpu = true;
        int idx = insn.fpuModrm & 7;
        if (idx == 0) idx = 1;  // FXCH with no operand defaults to ST(1)
        println("\t{{ long double tmp = ctx.fpu.ST(0).f80; ctx.fpu.ST(0).f80 = ctx.fpu.ST({}).f80; ctx.fpu.ST({}).f80 = tmp; }}", idx, idx);
        break;
    }
    
    case x86::InsnType::Fchs:
    {
        // FCHS - Change sign of ST(0)
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = -ctx.fpu.ST(0).f80;");
        break;
    }
    
    case x86::InsnType::Fabs:
    {
        // FABS - Absolute value of ST(0)
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_fabsl(ctx.fpu.ST(0).f80);");
        break;
    }
    
    case x86::InsnType::Ftst:
    {
        // FTST - Compare ST(0) with 0.0
        localVariables.fpu = true;
        println("\tctx.fpu.setCompareResult(ctx.fpu.ST(0).f80, 0.0L);");
        break;
    }
    
    case x86::InsnType::Fxam:
    {
        // FXAM - Examine ST(0) and set condition codes
        localVariables.fpu = true;
        println("\t// FXAM - examine ST(0) (simplified implementation)");
        println("\tctx.fpu.status.c1 = __builtin_signbit(ctx.fpu.ST(0).f80) ? 1 : 0;");
        println("\tif (__builtin_isnan(ctx.fpu.ST(0).f80)) {{ ctx.fpu.status.c3 = 0; ctx.fpu.status.c2 = 0; ctx.fpu.status.c0 = 1; }}");
        println("\telse if (__builtin_isinf(ctx.fpu.ST(0).f80)) {{ ctx.fpu.status.c3 = 0; ctx.fpu.status.c2 = 1; ctx.fpu.status.c0 = 1; }}");
        println("\telse if (ctx.fpu.ST(0).f80 == 0.0L) {{ ctx.fpu.status.c3 = 1; ctx.fpu.status.c2 = 0; ctx.fpu.status.c0 = 0; }}");
        println("\telse {{ ctx.fpu.status.c3 = 0; ctx.fpu.status.c2 = 1; ctx.fpu.status.c0 = 0; }} // Normal");
        break;
    }
    
    case x86::InsnType::Fsqrt:
    {
        // FSQRT - Square root of ST(0)
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_sqrtl(ctx.fpu.ST(0).f80);");
        break;
    }
    
    case x86::InsnType::Fsin:
    {
        // FSIN - Sine of ST(0)
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_sinl(ctx.fpu.ST(0).f80);");
        break;
    }
    
    case x86::InsnType::Fcos:
    {
        // FCOS - Cosine of ST(0)
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_cosl(ctx.fpu.ST(0).f80);");
        break;
    }
    
    case x86::InsnType::Fsincos:
    {
        // FSINCOS - Compute sin and cos, push cos, replace ST(0) with sin
        localVariables.fpu = true;
        println("\t{{");
        println("\t\tlong double x = ctx.fpu.ST(0).f80;");
        println("\t\tctx.fpu.ST(0).f80 = __builtin_sinl(x);");
        println("\t\tctx.fpu.push(__builtin_cosl(x));");
        println("\t}}");
        break;
    }
    
    case x86::InsnType::Fptan:
    {
        // FPTAN - Partial tangent, push 1.0
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_tanl(ctx.fpu.ST(0).f80);");
        println("\tctx.fpu.push(1.0L);");
        break;
    }
    
    case x86::InsnType::Fpatan:
    {
        // FPATAN - Partial arctangent: ST(1) = atan2(ST(1), ST(0)), pop
        localVariables.fpu = true;
        println("\tctx.fpu.ST(1).f80 = __builtin_atan2l(ctx.fpu.ST(1).f80, ctx.fpu.ST(0).f80);");
        println("\tctx.fpu.pop();");
        break;
    }
    
    case x86::InsnType::Fscale:
    {
        // FSCALE - ST(0) = ST(0) * 2^trunc(ST(1))
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_scalbnl(ctx.fpu.ST(0).f80, static_cast<int>(ctx.fpu.ST(1).f80));");
        break;
    }
    
    case x86::InsnType::Frndint:
    {
        // FRNDINT - Round ST(0) to integer
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_nearbyintl(ctx.fpu.ST(0).f80);");
        break;
    }
    
    case x86::InsnType::F2xm1:
    {
        // F2XM1 - ST(0) = 2^ST(0) - 1 (for -1 <= ST(0) <= 1)
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_exp2l(ctx.fpu.ST(0).f80) - 1.0L;");
        break;
    }
    
    case x86::InsnType::Fyl2x:
    {
        // FYL2X - ST(1) = ST(1) * log2(ST(0)), pop
        localVariables.fpu = true;
        println("\tctx.fpu.ST(1).f80 = ctx.fpu.ST(1).f80 * __builtin_log2l(ctx.fpu.ST(0).f80);");
        println("\tctx.fpu.pop();");
        break;
    }
    
    case x86::InsnType::Fyl2xp1:
    {
        // FYL2XP1 - ST(1) = ST(1) * log2(ST(0) + 1), pop
        localVariables.fpu = true;
        println("\tctx.fpu.ST(1).f80 = ctx.fpu.ST(1).f80 * __builtin_log2l(ctx.fpu.ST(0).f80 + 1.0L);");
        println("\tctx.fpu.pop();");
        break;
    }
    
    case x86::InsnType::Fprem:
    {
        // FPREM/FPREM1 - Partial remainder
        localVariables.fpu = true;
        println("\tctx.fpu.ST(0).f80 = __builtin_fmodl(ctx.fpu.ST(0).f80, ctx.fpu.ST(1).f80);");
        break;
    }
    
    case x86::InsnType::Fdecstp:
    {
        // FDECSTP - Decrement stack pointer (rotate stack)
        localVariables.fpu = true;
        println("\tctx.fpu.status.top = (ctx.fpu.status.top - 1) & 7;");
        break;
    }
    
    case x86::InsnType::Fincstp:
    {
        // FINCSTP - Increment stack pointer (rotate stack)
        localVariables.fpu = true;
        println("\tctx.fpu.status.top = (ctx.fpu.status.top + 1) & 7;");
        break;
    }
    
    case x86::InsnType::Ffree:
    {
        // FFREE - Mark register as empty
        localVariables.fpu = true;
        int idx = insn.fpuModrm & 7;
        println("\tctx.fpu.tags.setEmpty(ctx.fpu.getPhysicalIndex({}));", idx);
        break;
    }
    
    case x86::InsnType::Fldcw:
    {
        // FLDCW - Load control word from memory
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\t*reinterpret_cast<uint16_t*>(&ctx.fpu.control) = X86_LOAD_U16({});", addr);
        break;
    }
    
    case x86::InsnType::Fstcw:
    {
        // FNSTCW - Store control word to memory
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\tX86_STORE_U16({}, *reinterpret_cast<uint16_t*>(&ctx.fpu.control));", addr);
        break;
    }
    
    case x86::InsnType::Fstsw:
    {
        // FNSTSW - Store status word
        localVariables.fpu = true;
        
        if (insn.fpuModrm == 0xE0)
        {
            // FNSTSW AX - store status word to AX
            localVariables.eax = true;
            println("\tctx.eax.u16 = *reinterpret_cast<uint16_t*>(&ctx.fpu.status);");
        }
        else
        {
            // FNSTSW m16 - store status word to memory
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            println("\tX86_STORE_U16({}, *reinterpret_cast<uint16_t*>(&ctx.fpu.status));", addr);
        }
        break;
    }
    
    case x86::InsnType::Fldenv:
    {
        // FLDENV - Load FPU environment (14/28 bytes)
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\t// FLDENV - load FPU environment from {}", addr);
        println("\t*reinterpret_cast<uint16_t*>(&ctx.fpu.control) = X86_LOAD_U16({});", addr);
        println("\t*reinterpret_cast<uint16_t*>(&ctx.fpu.status) = X86_LOAD_U16({} + 4);", addr);
        println("\tctx.fpu.tags.tags = X86_LOAD_U16({} + 8);", addr);
        break;
    }
    
    case x86::InsnType::Fstenv:
    {
        // FNSTENV - Store FPU environment
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\t// FNSTENV - store FPU environment to {}", addr);
        println("\tX86_STORE_U16({}, *reinterpret_cast<uint16_t*>(&ctx.fpu.control));", addr);
        println("\tX86_STORE_U16({} + 4, *reinterpret_cast<uint16_t*>(&ctx.fpu.status));", addr);
        println("\tX86_STORE_U16({} + 8, ctx.fpu.tags.tags);", addr);
        break;
    }
    
    case x86::InsnType::Fsave:
    {
        // FNSAVE - Save complete FPU state (94/108 bytes)
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\t// FNSAVE - save FPU state (simplified - saves environment + registers)");
        println("\tX86_STORE_U16({}, *reinterpret_cast<uint16_t*>(&ctx.fpu.control));", addr);
        println("\tX86_STORE_U16({} + 4, *reinterpret_cast<uint16_t*>(&ctx.fpu.status));", addr);
        println("\tX86_STORE_U16({} + 8, ctx.fpu.tags.tags);", addr);
        println("\tfor (int i = 0; i < 8; i++) {{");
        println("\t\tX86_STORE_F80({} + 28 + i * 10, ctx.fpu.st[i].f80);", addr);
        println("\t}}");
        println("\tctx.fpu.tags.tags = 0xFFFF; // Reinitialize FPU");
        break;
    }
    
    case x86::InsnType::Frstor:
    {
        // FRSTOR - Restore complete FPU state
        localVariables.fpu = true;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\t// FRSTOR - restore FPU state");
        println("\t*reinterpret_cast<uint16_t*>(&ctx.fpu.control) = X86_LOAD_U16({});", addr);
        println("\t*reinterpret_cast<uint16_t*>(&ctx.fpu.status) = X86_LOAD_U16({} + 4);", addr);
        println("\tctx.fpu.tags.tags = X86_LOAD_U16({} + 8);", addr);
        println("\tfor (int i = 0; i < 8; i++) {{");
        println("\t\tctx.fpu.st[i].f80 = X86_LOAD_F80({} + 28 + i * 10);", addr);
        println("\t}}");
        break;
    }
    
    case x86::InsnType::Finit:
    {
        // FNINIT - Initialize FPU
        localVariables.fpu = true;
        println("\t// FNINIT - initialize FPU");
        println("\t*reinterpret_cast<uint16_t*>(&ctx.fpu.control) = 0x037F;"); // Default control word
        println("\t*reinterpret_cast<uint16_t*>(&ctx.fpu.status) = 0;");
        println("\tctx.fpu.tags.tags = 0xFFFF;"); // All empty
        break;
    }
    
    case x86::InsnType::Fclex:
    {
        // FNCLEX - Clear exceptions
        localVariables.fpu = true;
        println("\tctx.fpu.status.ie = 0;");
        println("\tctx.fpu.status.de = 0;");
        println("\tctx.fpu.status.ze = 0;");
        println("\tctx.fpu.status.oe = 0;");
        println("\tctx.fpu.status.ue = 0;");
        println("\tctx.fpu.status.pe = 0;");
        println("\tctx.fpu.status.sf = 0;");
        println("\tctx.fpu.status.es = 0;");
        println("\tctx.fpu.status.b = 0;");
        break;
    }

    // ==================== MMX Instructions ====================
    
    case x86::InsnType::Movd:
    {
        // MOVD moves 32 bits between MMX register and GPR/memory
        if (insn.op[0].type == x86::OpType::Reg && insn.op[0].reg >= x86::MM0 && insn.op[0].reg <= x86::MM7)
        {
            // MOVD mm, r/m32 - load 32-bit value, zero-extend to 64-bit
            int mmIdx = insn.op[0].reg - x86::MM0;
            std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
            println("\tctx.mm[{}].u64 = static_cast<uint64_t>({});", mmIdx, src);
        }
        else
        {
            // MOVD r/m32, mm - store low 32 bits
            int mmIdx = insn.op[1].reg - x86::MM0;
            println("\t{};", FormatOperandWrite(insn.op[0], fmt::format("ctx.mm[{}].u32[0]", mmIdx), 4, localVariables));
        }
        break;
    }
    
    case x86::InsnType::Movq:
    {
        // MOVQ moves 64 bits between MMX registers or MMX register and memory
        if (insn.op[0].type == x86::OpType::Reg && insn.op[0].reg >= x86::MM0 && insn.op[0].reg <= x86::MM7)
        {
            // MOVQ mm, mm/m64 - load 64-bit value
            int dstIdx = insn.op[0].reg - x86::MM0;
            if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
            {
                // mm-to-mm
                int srcIdx = insn.op[1].reg - x86::MM0;
                println("\tctx.mm[{}].u64 = ctx.mm[{}].u64;", dstIdx, srcIdx);
            }
            else
            {
                // m64-to-mm
                std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
                println("\tctx.mm[{}].u64 = X86_LOAD_U64({});", dstIdx, addr);
            }
        }
        else
        {
            // MOVQ m64, mm - store 64-bit value
            int srcIdx = insn.op[1].reg - x86::MM0;
            std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
            println("\tX86_STORE_U64({}, ctx.mm[{}].u64);", addr, srcIdx);
        }
        break;
    }
    
    case x86::InsnType::Emms:
        // EMMS - Empty MMX State: marks all FPU registers as empty
        // This allows FPU instructions to be used after MMX instructions
        println("\tctx.fpu.tags.tags = 0xFFFF; // All registers empty");
        break;

    case x86::InsnType::Pand:
    {
        // PAND mm, mm/m64 - Packed AND
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\tctx.mm[{}].u64 &= ctx.mm[{}].u64;", dstIdx, srcIdx);
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\tctx.mm[{}].u64 &= X86_LOAD_U64({});", dstIdx, addr);
        }
        break;
    }

    case x86::InsnType::Pandn:
    {
        // PANDN mm, mm/m64 - Packed AND NOT (dst = ~dst & src)
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\tctx.mm[{}].u64 = ~ctx.mm[{}].u64 & ctx.mm[{}].u64;", dstIdx, dstIdx, srcIdx);
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\tctx.mm[{}].u64 = ~ctx.mm[{}].u64 & X86_LOAD_U64({});", dstIdx, dstIdx, addr);
        }
        break;
    }

    case x86::InsnType::Por:
    {
        // POR mm, mm/m64 - Packed OR
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\tctx.mm[{}].u64 |= ctx.mm[{}].u64;", dstIdx, srcIdx);
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\tctx.mm[{}].u64 |= X86_LOAD_U64({});", dstIdx, addr);
        }
        break;
    }

    case x86::InsnType::Pxor:
    {
        // PXOR mm, mm/m64 - Packed XOR
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\tctx.mm[{}].u64 ^= ctx.mm[{}].u64;", dstIdx, srcIdx);
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\tctx.mm[{}].u64 ^= X86_LOAD_U64({});", dstIdx, addr);
        }
        break;
    }

    case x86::InsnType::Pcmpgtd:
    {
        // PCMPGTD mm, mm/m64 - Packed Compare Greater Than Dword
        // For each dword: dst = (dst > src) ? 0xFFFFFFFF : 0
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < 2; i++)");
            println("\t\t\tctx.mm[{}].s32[i] = (ctx.mm[{}].s32[i] > ctx.mm[{}].s32[i]) ? -1 : 0;", dstIdx, dstIdx, srcIdx);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tint32_t src[2];");
            println("\t\tuint64_t srcVal = X86_LOAD_U64({});", addr);
            println("\t\tsrc[0] = static_cast<int32_t>(srcVal);");
            println("\t\tsrc[1] = static_cast<int32_t>(srcVal >> 32);");
            println("\t\tfor (int i = 0; i < 2; i++)");
            println("\t\t\tctx.mm[{}].s32[i] = (ctx.mm[{}].s32[i] > src[i]) ? -1 : 0;", dstIdx, dstIdx);
            println("\t}}");
        }
        break;
    }

    // MMX Packed Compare Equal operations
    case x86::InsnType::Pcmpeqb:
    case x86::InsnType::Pcmpeqw:
    case x86::InsnType::Pcmpeqd:
    {
        int dstIdx = insn.op[0].reg - x86::MM0;
        int elemCount = (insn.type == x86::InsnType::Pcmpeqb) ? 8 : 
                        (insn.type == x86::InsnType::Pcmpeqw) ? 4 : 2;
        const char* elemType = (insn.type == x86::InsnType::Pcmpeqb) ? "u8" : 
                               (insn.type == x86::InsnType::Pcmpeqw) ? "u16" : "u32";
        const char* signedType = (insn.type == x86::InsnType::Pcmpeqb) ? "int8_t" : 
                                 (insn.type == x86::InsnType::Pcmpeqw) ? "int16_t" : "int32_t";
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] == ctx.mm[{}].{}[i]) ? ({})(-1) : 0;", 
                    dstIdx, elemType, dstIdx, elemType, srcIdx, elemType, signedType);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; {} elem[{}]; }} src;", signedType, elemCount);
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] == src.elem[i]) ? ({})(-1) : 0;", 
                    dstIdx, elemType, dstIdx, elemType, signedType);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Pcmpgtb:
    case x86::InsnType::Pcmpgtw:
    {
        int dstIdx = insn.op[0].reg - x86::MM0;
        int elemCount = (insn.type == x86::InsnType::Pcmpgtb) ? 8 : 4;
        const char* elemType = (insn.type == x86::InsnType::Pcmpgtb) ? "s8" : "s16";
        const char* signedType = (insn.type == x86::InsnType::Pcmpgtb) ? "int8_t" : "int16_t";
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] > ctx.mm[{}].{}[i]) ? ({})(-1) : 0;", 
                    dstIdx, elemType, dstIdx, elemType, srcIdx, elemType, signedType);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; {} elem[{}]; }} src;", signedType, elemCount);
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] > src.elem[i]) ? ({})(-1) : 0;", 
                    dstIdx, elemType, dstIdx, elemType, signedType);
            println("\t}}");
        }
        break;
    }

    // MMX Packed Add/Subtract operations
    case x86::InsnType::Paddb:
    case x86::InsnType::Paddw:
    case x86::InsnType::Paddd:
    case x86::InsnType::Psubb:
    case x86::InsnType::Psubw:
    case x86::InsnType::Psubd:
    {
        int dstIdx = insn.op[0].reg - x86::MM0;
        bool isAdd = (insn.type == x86::InsnType::Paddb || 
                      insn.type == x86::InsnType::Paddw || 
                      insn.type == x86::InsnType::Paddd);
        int elemCount, elemSize;
        const char* elemType;
        
        if (insn.type == x86::InsnType::Paddb || insn.type == x86::InsnType::Psubb) {
            elemCount = 8; elemSize = 8; elemType = "u8";
        } else if (insn.type == x86::InsnType::Paddw || insn.type == x86::InsnType::Psubw) {
            elemCount = 4; elemSize = 16; elemType = "u16";
        } else {
            elemCount = 2; elemSize = 32; elemType = "u32";
        }
        
        const char* op = isAdd ? "+" : "-";
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = ctx.mm[{}].{}[i] {} ctx.mm[{}].{}[i];", 
                    dstIdx, elemType, dstIdx, elemType, op, srcIdx, elemType);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            const char* intType = (elemSize == 8) ? "uint8_t" : (elemSize == 16) ? "uint16_t" : "uint32_t";
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; {} elem[{}]; }} src;", intType, elemCount);
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = ctx.mm[{}].{}[i] {} src.elem[i];", 
                    dstIdx, elemType, dstIdx, elemType, op);
            println("\t}}");
        }
        break;
    }

    // MMX Unpack operations
    case x86::InsnType::Punpcklbw:
    case x86::InsnType::Punpcklwd:
    case x86::InsnType::Punpckldq:
    {
        int dstIdx = insn.op[0].reg - x86::MM0;
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            if (insn.type == x86::InsnType::Punpcklbw) {
                println("\t\tuint8_t d0 = ctx.mm[{}].u8[0], d1 = ctx.mm[{}].u8[1], d2 = ctx.mm[{}].u8[2], d3 = ctx.mm[{}].u8[3];", dstIdx, dstIdx, dstIdx, dstIdx);
                println("\t\tuint8_t s0 = ctx.mm[{}].u8[0], s1 = ctx.mm[{}].u8[1], s2 = ctx.mm[{}].u8[2], s3 = ctx.mm[{}].u8[3];", srcIdx, srcIdx, srcIdx, srcIdx);
                println("\t\tctx.mm[{}].u8[0] = d0; ctx.mm[{}].u8[1] = s0;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[2] = d1; ctx.mm[{}].u8[3] = s1;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[4] = d2; ctx.mm[{}].u8[5] = s2;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[6] = d3; ctx.mm[{}].u8[7] = s3;", dstIdx, dstIdx);
            } else if (insn.type == x86::InsnType::Punpcklwd) {
                println("\t\tuint16_t d0 = ctx.mm[{}].u16[0], d1 = ctx.mm[{}].u16[1];", dstIdx, dstIdx);
                println("\t\tuint16_t s0 = ctx.mm[{}].u16[0], s1 = ctx.mm[{}].u16[1];", srcIdx, srcIdx);
                println("\t\tctx.mm[{}].u16[0] = d0; ctx.mm[{}].u16[1] = s0;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u16[2] = d1; ctx.mm[{}].u16[3] = s1;", dstIdx, dstIdx);
            } else {
                println("\t\tuint32_t d0 = ctx.mm[{}].u32[0];", dstIdx);
                println("\t\tuint32_t s0 = ctx.mm[{}].u32[0];", srcIdx);
                println("\t\tctx.mm[{}].u32[0] = d0; ctx.mm[{}].u32[1] = s0;", dstIdx, dstIdx);
            }
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tuint64_t srcVal = X86_LOAD_U64({});", addr);
            if (insn.type == x86::InsnType::Punpcklbw) {
                println("\t\tuint8_t d0 = ctx.mm[{}].u8[0], d1 = ctx.mm[{}].u8[1], d2 = ctx.mm[{}].u8[2], d3 = ctx.mm[{}].u8[3];", dstIdx, dstIdx, dstIdx, dstIdx);
                println("\t\tuint8_t s0 = srcVal & 0xFF, s1 = (srcVal >> 8) & 0xFF, s2 = (srcVal >> 16) & 0xFF, s3 = (srcVal >> 24) & 0xFF;");
                println("\t\tctx.mm[{}].u8[0] = d0; ctx.mm[{}].u8[1] = s0;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[2] = d1; ctx.mm[{}].u8[3] = s1;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[4] = d2; ctx.mm[{}].u8[5] = s2;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[6] = d3; ctx.mm[{}].u8[7] = s3;", dstIdx, dstIdx);
            } else if (insn.type == x86::InsnType::Punpcklwd) {
                println("\t\tuint16_t d0 = ctx.mm[{}].u16[0], d1 = ctx.mm[{}].u16[1];", dstIdx, dstIdx);
                println("\t\tuint16_t s0 = srcVal & 0xFFFF, s1 = (srcVal >> 16) & 0xFFFF;");
                println("\t\tctx.mm[{}].u16[0] = d0; ctx.mm[{}].u16[1] = s0;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u16[2] = d1; ctx.mm[{}].u16[3] = s1;", dstIdx, dstIdx);
            } else {
                println("\t\tuint32_t d0 = ctx.mm[{}].u32[0];", dstIdx);
                println("\t\tuint32_t s0 = static_cast<uint32_t>(srcVal);");
                println("\t\tctx.mm[{}].u32[0] = d0; ctx.mm[{}].u32[1] = s0;", dstIdx, dstIdx);
            }
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Punpckhbw:
    case x86::InsnType::Punpckhwd:
    case x86::InsnType::Punpckhdq:
    {
        int dstIdx = insn.op[0].reg - x86::MM0;
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            if (insn.type == x86::InsnType::Punpckhbw) {
                println("\t\tuint8_t d4 = ctx.mm[{}].u8[4], d5 = ctx.mm[{}].u8[5], d6 = ctx.mm[{}].u8[6], d7 = ctx.mm[{}].u8[7];", dstIdx, dstIdx, dstIdx, dstIdx);
                println("\t\tuint8_t s4 = ctx.mm[{}].u8[4], s5 = ctx.mm[{}].u8[5], s6 = ctx.mm[{}].u8[6], s7 = ctx.mm[{}].u8[7];", srcIdx, srcIdx, srcIdx, srcIdx);
                println("\t\tctx.mm[{}].u8[0] = d4; ctx.mm[{}].u8[1] = s4;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[2] = d5; ctx.mm[{}].u8[3] = s5;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[4] = d6; ctx.mm[{}].u8[5] = s6;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[6] = d7; ctx.mm[{}].u8[7] = s7;", dstIdx, dstIdx);
            } else if (insn.type == x86::InsnType::Punpckhwd) {
                println("\t\tuint16_t d2 = ctx.mm[{}].u16[2], d3 = ctx.mm[{}].u16[3];", dstIdx, dstIdx);
                println("\t\tuint16_t s2 = ctx.mm[{}].u16[2], s3 = ctx.mm[{}].u16[3];", srcIdx, srcIdx);
                println("\t\tctx.mm[{}].u16[0] = d2; ctx.mm[{}].u16[1] = s2;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u16[2] = d3; ctx.mm[{}].u16[3] = s3;", dstIdx, dstIdx);
            } else {
                println("\t\tuint32_t d1 = ctx.mm[{}].u32[1];", dstIdx);
                println("\t\tuint32_t s1 = ctx.mm[{}].u32[1];", srcIdx);
                println("\t\tctx.mm[{}].u32[0] = d1; ctx.mm[{}].u32[1] = s1;", dstIdx, dstIdx);
            }
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tuint64_t srcVal = X86_LOAD_U64({});", addr);
            if (insn.type == x86::InsnType::Punpckhbw) {
                println("\t\tuint8_t d4 = ctx.mm[{}].u8[4], d5 = ctx.mm[{}].u8[5], d6 = ctx.mm[{}].u8[6], d7 = ctx.mm[{}].u8[7];", dstIdx, dstIdx, dstIdx, dstIdx);
                println("\t\tuint8_t s4 = (srcVal >> 32) & 0xFF, s5 = (srcVal >> 40) & 0xFF, s6 = (srcVal >> 48) & 0xFF, s7 = (srcVal >> 56) & 0xFF;");
                println("\t\tctx.mm[{}].u8[0] = d4; ctx.mm[{}].u8[1] = s4;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[2] = d5; ctx.mm[{}].u8[3] = s5;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[4] = d6; ctx.mm[{}].u8[5] = s6;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u8[6] = d7; ctx.mm[{}].u8[7] = s7;", dstIdx, dstIdx);
            } else if (insn.type == x86::InsnType::Punpckhwd) {
                println("\t\tuint16_t d2 = ctx.mm[{}].u16[2], d3 = ctx.mm[{}].u16[3];", dstIdx, dstIdx);
                println("\t\tuint16_t s2 = (srcVal >> 32) & 0xFFFF, s3 = (srcVal >> 48) & 0xFFFF;");
                println("\t\tctx.mm[{}].u16[0] = d2; ctx.mm[{}].u16[1] = s2;", dstIdx, dstIdx);
                println("\t\tctx.mm[{}].u16[2] = d3; ctx.mm[{}].u16[3] = s3;", dstIdx, dstIdx);
            } else {
                println("\t\tuint32_t d1 = ctx.mm[{}].u32[1];", dstIdx);
                println("\t\tuint32_t s1 = static_cast<uint32_t>(srcVal >> 32);");
                println("\t\tctx.mm[{}].u32[0] = d1; ctx.mm[{}].u32[1] = s1;", dstIdx, dstIdx);
            }
            println("\t}}");
        }
        break;
    }

    // MMX Pack operations
    case x86::InsnType::Packsswb:
    {
        // Pack signed words to signed bytes with saturation
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tauto saturate = [](int16_t v) -> int8_t {{ return (v < -128) ? -128 : (v > 127) ? 127 : (int8_t)v; }};");
            println("\t\tint8_t r[8];");
            println("\t\tr[0] = saturate(ctx.mm[{}].s16[0]);", dstIdx);
            println("\t\tr[1] = saturate(ctx.mm[{}].s16[1]);", dstIdx);
            println("\t\tr[2] = saturate(ctx.mm[{}].s16[2]);", dstIdx);
            println("\t\tr[3] = saturate(ctx.mm[{}].s16[3]);", dstIdx);
            println("\t\tr[4] = saturate(ctx.mm[{}].s16[0]);", srcIdx);
            println("\t\tr[5] = saturate(ctx.mm[{}].s16[1]);", srcIdx);
            println("\t\tr[6] = saturate(ctx.mm[{}].s16[2]);", srcIdx);
            println("\t\tr[7] = saturate(ctx.mm[{}].s16[3]);", srcIdx);
            println("\t\tfor (int i = 0; i < 8; i++) ctx.mm[{}].s8[i] = r[i];", dstIdx);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tauto saturate = [](int16_t v) -> int8_t {{ return (v < -128) ? -128 : (v > 127) ? 127 : (int8_t)v; }};");
            println("\t\tunion {{ uint64_t u64; int16_t s16[4]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tint8_t r[8];");
            println("\t\tr[0] = saturate(ctx.mm[{}].s16[0]);", dstIdx);
            println("\t\tr[1] = saturate(ctx.mm[{}].s16[1]);", dstIdx);
            println("\t\tr[2] = saturate(ctx.mm[{}].s16[2]);", dstIdx);
            println("\t\tr[3] = saturate(ctx.mm[{}].s16[3]);", dstIdx);
            println("\t\tr[4] = saturate(src.s16[0]);");
            println("\t\tr[5] = saturate(src.s16[1]);");
            println("\t\tr[6] = saturate(src.s16[2]);");
            println("\t\tr[7] = saturate(src.s16[3]);");
            println("\t\tfor (int i = 0; i < 8; i++) ctx.mm[{}].s8[i] = r[i];", dstIdx);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Packssdw:
    {
        // Pack signed dwords to signed words with saturation
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tauto saturate = [](int32_t v) -> int16_t {{ return (v < -32768) ? -32768 : (v > 32767) ? 32767 : (int16_t)v; }};");
            println("\t\tint16_t r[4];");
            println("\t\tr[0] = saturate(ctx.mm[{}].s32[0]);", dstIdx);
            println("\t\tr[1] = saturate(ctx.mm[{}].s32[1]);", dstIdx);
            println("\t\tr[2] = saturate(ctx.mm[{}].s32[0]);", srcIdx);
            println("\t\tr[3] = saturate(ctx.mm[{}].s32[1]);", srcIdx);
            println("\t\tfor (int i = 0; i < 4; i++) ctx.mm[{}].s16[i] = r[i];", dstIdx);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tauto saturate = [](int32_t v) -> int16_t {{ return (v < -32768) ? -32768 : (v > 32767) ? 32767 : (int16_t)v; }};");
            println("\t\tunion {{ uint64_t u64; int32_t s32[2]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tint16_t r[4];");
            println("\t\tr[0] = saturate(ctx.mm[{}].s32[0]);", dstIdx);
            println("\t\tr[1] = saturate(ctx.mm[{}].s32[1]);", dstIdx);
            println("\t\tr[2] = saturate(src.s32[0]);");
            println("\t\tr[3] = saturate(src.s32[1]);");
            println("\t\tfor (int i = 0; i < 4; i++) ctx.mm[{}].s16[i] = r[i];", dstIdx);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Packuswb:
    {
        // Pack signed words to unsigned bytes with saturation
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tauto saturate = [](int16_t v) -> uint8_t {{ return (v < 0) ? 0 : (v > 255) ? 255 : (uint8_t)v; }};");
            println("\t\tuint8_t r[8];");
            println("\t\tr[0] = saturate(ctx.mm[{}].s16[0]);", dstIdx);
            println("\t\tr[1] = saturate(ctx.mm[{}].s16[1]);", dstIdx);
            println("\t\tr[2] = saturate(ctx.mm[{}].s16[2]);", dstIdx);
            println("\t\tr[3] = saturate(ctx.mm[{}].s16[3]);", dstIdx);
            println("\t\tr[4] = saturate(ctx.mm[{}].s16[0]);", srcIdx);
            println("\t\tr[5] = saturate(ctx.mm[{}].s16[1]);", srcIdx);
            println("\t\tr[6] = saturate(ctx.mm[{}].s16[2]);", srcIdx);
            println("\t\tr[7] = saturate(ctx.mm[{}].s16[3]);", srcIdx);
            println("\t\tfor (int i = 0; i < 8; i++) ctx.mm[{}].u8[i] = r[i];", dstIdx);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tauto saturate = [](int16_t v) -> uint8_t {{ return (v < 0) ? 0 : (v > 255) ? 255 : (uint8_t)v; }};");
            println("\t\tunion {{ uint64_t u64; int16_t s16[4]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tuint8_t r[8];");
            println("\t\tr[0] = saturate(ctx.mm[{}].s16[0]);", dstIdx);
            println("\t\tr[1] = saturate(ctx.mm[{}].s16[1]);", dstIdx);
            println("\t\tr[2] = saturate(ctx.mm[{}].s16[2]);", dstIdx);
            println("\t\tr[3] = saturate(ctx.mm[{}].s16[3]);", dstIdx);
            println("\t\tr[4] = saturate(src.s16[0]);");
            println("\t\tr[5] = saturate(src.s16[1]);");
            println("\t\tr[6] = saturate(src.s16[2]);");
            println("\t\tr[7] = saturate(src.s16[3]);");
            println("\t\tfor (int i = 0; i < 8; i++) ctx.mm[{}].u8[i] = r[i];", dstIdx);
            println("\t}}");
        }
        break;
    }

    // MMX Multiply operations
    case x86::InsnType::Pmullw:
    {
        // Packed Multiply Low Word
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < 4; i++)");
            println("\t\t\tctx.mm[{}].s16[i] = (int16_t)(ctx.mm[{}].s16[i] * ctx.mm[{}].s16[i]);", dstIdx, dstIdx, srcIdx);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; int16_t s16[4]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tfor (int i = 0; i < 4; i++)");
            println("\t\t\tctx.mm[{}].s16[i] = (int16_t)(ctx.mm[{}].s16[i] * src.s16[i]);", dstIdx, dstIdx);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Pmulhw:
    {
        // Packed Multiply High Word
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < 4; i++)");
            println("\t\t\tctx.mm[{}].s16[i] = (int16_t)(((int32_t)ctx.mm[{}].s16[i] * (int32_t)ctx.mm[{}].s16[i]) >> 16);", dstIdx, dstIdx, srcIdx);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; int16_t s16[4]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tfor (int i = 0; i < 4; i++)");
            println("\t\t\tctx.mm[{}].s16[i] = (int16_t)(((int32_t)ctx.mm[{}].s16[i] * (int32_t)src.s16[i]) >> 16);", dstIdx, dstIdx);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Pmaddwd:
    {
        // Packed Multiply and Add Word to Dword
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tint32_t r0 = (int32_t)ctx.mm[{}].s16[0] * (int32_t)ctx.mm[{}].s16[0] + (int32_t)ctx.mm[{}].s16[1] * (int32_t)ctx.mm[{}].s16[1];", dstIdx, srcIdx, dstIdx, srcIdx);
            println("\t\tint32_t r1 = (int32_t)ctx.mm[{}].s16[2] * (int32_t)ctx.mm[{}].s16[2] + (int32_t)ctx.mm[{}].s16[3] * (int32_t)ctx.mm[{}].s16[3];", dstIdx, srcIdx, dstIdx, srcIdx);
            println("\t\tctx.mm[{}].s32[0] = r0;", dstIdx);
            println("\t\tctx.mm[{}].s32[1] = r1;", dstIdx);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; int16_t s16[4]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tint32_t r0 = (int32_t)ctx.mm[{}].s16[0] * (int32_t)src.s16[0] + (int32_t)ctx.mm[{}].s16[1] * (int32_t)src.s16[1];", dstIdx, dstIdx);
            println("\t\tint32_t r1 = (int32_t)ctx.mm[{}].s16[2] * (int32_t)src.s16[2] + (int32_t)ctx.mm[{}].s16[3] * (int32_t)src.s16[3];", dstIdx, dstIdx);
            println("\t\tctx.mm[{}].s32[0] = r0;", dstIdx);
            println("\t\tctx.mm[{}].s32[1] = r1;", dstIdx);
            println("\t}}");
        }
        break;
    }

    // MMX Shift operations
    case x86::InsnType::Psrlw:
    case x86::InsnType::Psrld:
    case x86::InsnType::Psrlq:
    case x86::InsnType::Psraw:
    case x86::InsnType::Psrad:
    case x86::InsnType::Psllw:
    case x86::InsnType::Pslld:
    case x86::InsnType::Psllq:
    {
        int dstIdx = insn.op[0].reg - x86::MM0;
        bool isRight = (insn.type == x86::InsnType::Psrlw || insn.type == x86::InsnType::Psrld || 
                        insn.type == x86::InsnType::Psrlq || insn.type == x86::InsnType::Psraw || 
                        insn.type == x86::InsnType::Psrad);
        bool isArithmetic = (insn.type == x86::InsnType::Psraw || insn.type == x86::InsnType::Psrad);
        
        int elemCount;
        const char* elemType;
        int elemBits;
        
        if (insn.type == x86::InsnType::Psrlw || insn.type == x86::InsnType::Psraw || insn.type == x86::InsnType::Psllw) {
            elemCount = 4; elemType = isArithmetic ? "s16" : "u16"; elemBits = 16;
        } else if (insn.type == x86::InsnType::Psrld || insn.type == x86::InsnType::Psrad || insn.type == x86::InsnType::Pslld) {
            elemCount = 2; elemType = isArithmetic ? "s32" : "u32"; elemBits = 32;
        } else {
            elemCount = 1; elemType = "u64"; elemBits = 64;
        }
        
        const char* shiftOp = isRight ? ">>" : "<<";
        
        if (insn.op[1].type == x86::OpType::Imm)
        {
            int shift = static_cast<int>(insn.op[1].imm);
            if (elemCount == 1) {
                println("\tctx.mm[{}].{} {}= {};", dstIdx, elemType, shiftOp, shift);
            } else {
                println("\t{{");
                println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
                println("\t\t\tctx.mm[{}].{}[i] {}= {};", dstIdx, elemType, shiftOp, shift);
                println("\t}}");
            }
        }
        else if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tint shift = static_cast<int>(ctx.mm[{}].u64);", srcIdx);
            println("\t\tif (shift >= {}) {{", elemBits);
            if (isArithmetic) {
                if (elemCount == 1) {
                    println("\t\t\tctx.mm[{}].{} = (ctx.mm[{}].{} < 0) ? -1 : 0;", dstIdx, elemType, dstIdx, elemType);
                } else {
                    println("\t\t\tfor (int i = 0; i < {}; i++)", elemCount);
                    println("\t\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] < 0) ? -1 : 0;", dstIdx, elemType, dstIdx, elemType);
                }
            } else {
                if (elemCount == 1) {
                    println("\t\t\tctx.mm[{}].{} = 0;", dstIdx, elemType);
                } else {
                    println("\t\t\tfor (int i = 0; i < {}; i++) ctx.mm[{}].{}[i] = 0;", elemCount, dstIdx, elemType);
                }
            }
            println("\t\t}} else {{");
            if (elemCount == 1) {
                println("\t\t\tctx.mm[{}].{} {}= shift;", dstIdx, elemType, shiftOp);
            } else {
                println("\t\t\tfor (int i = 0; i < {}; i++)", elemCount);
                println("\t\t\t\tctx.mm[{}].{}[i] {}= shift;", dstIdx, elemType, shiftOp);
            }
            println("\t\t}}");
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tint shift = static_cast<int>(X86_LOAD_U64({}));", addr);
            println("\t\tif (shift >= {}) {{", elemBits);
            if (isArithmetic) {
                if (elemCount == 1) {
                    println("\t\t\tctx.mm[{}].{} = (ctx.mm[{}].{} < 0) ? -1 : 0;", dstIdx, elemType, dstIdx, elemType);
                } else {
                    println("\t\t\tfor (int i = 0; i < {}; i++)", elemCount);
                    println("\t\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] < 0) ? -1 : 0;", dstIdx, elemType, dstIdx, elemType);
                }
            } else {
                if (elemCount == 1) {
                    println("\t\t\tctx.mm[{}].{} = 0;", dstIdx, elemType);
                } else {
                    println("\t\t\tfor (int i = 0; i < {}; i++) ctx.mm[{}].{}[i] = 0;", elemCount, dstIdx, elemType);
                }
            }
            println("\t\t}} else {{");
            if (elemCount == 1) {
                println("\t\t\tctx.mm[{}].{} {}= shift;", dstIdx, elemType, shiftOp);
            } else {
                println("\t\t\tfor (int i = 0; i < {}; i++)", elemCount);
                println("\t\t\t\tctx.mm[{}].{}[i] {}= shift;", dstIdx, elemType, shiftOp);
            }
            println("\t\t}}");
            println("\t}}");
        }
        break;
    }

    // SSE/MMX Extensions
    case x86::InsnType::Pshufw:
    {
        // Shuffle words according to immediate control byte
        int dstIdx = insn.op[0].reg - x86::MM0;
        int imm = static_cast<int>(insn.op[2].imm);
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tuint16_t src[4];");
            println("\t\tfor (int i = 0; i < 4; i++) src[i] = ctx.mm[{}].u16[i];", srcIdx);
            println("\t\tctx.mm[{}].u16[0] = src[{} & 3];", dstIdx, imm);
            println("\t\tctx.mm[{}].u16[1] = src[({} >> 2) & 3];", dstIdx, imm);
            println("\t\tctx.mm[{}].u16[2] = src[({} >> 4) & 3];", dstIdx, imm);
            println("\t\tctx.mm[{}].u16[3] = src[({} >> 6) & 3];", dstIdx, imm);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; uint16_t u16[4]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tctx.mm[{}].u16[0] = src.u16[{} & 3];", dstIdx, imm);
            println("\t\tctx.mm[{}].u16[1] = src.u16[({} >> 2) & 3];", dstIdx, imm);
            println("\t\tctx.mm[{}].u16[2] = src.u16[({} >> 4) & 3];", dstIdx, imm);
            println("\t\tctx.mm[{}].u16[3] = src.u16[({} >> 6) & 3];", dstIdx, imm);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Pavgb:
    case x86::InsnType::Pavgw:
    {
        // Packed Average (rounded)
        int dstIdx = insn.op[0].reg - x86::MM0;
        int elemCount = (insn.type == x86::InsnType::Pavgb) ? 8 : 4;
        const char* elemType = (insn.type == x86::InsnType::Pavgb) ? "u8" : "u16";
        const char* intType = (insn.type == x86::InsnType::Pavgb) ? "uint8_t" : "uint16_t";
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = ({})((ctx.mm[{}].{}[i] + ctx.mm[{}].{}[i] + 1) >> 1);", 
                    dstIdx, elemType, intType, dstIdx, elemType, srcIdx, elemType);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; {} elem[{}]; }} src;", intType, elemCount);
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = ({})((ctx.mm[{}].{}[i] + src.elem[i] + 1) >> 1);", 
                    dstIdx, elemType, intType, dstIdx, elemType);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Pminub:
    case x86::InsnType::Pmaxub:
    case x86::InsnType::Pminsw:
    case x86::InsnType::Pmaxsw:
    {
        // Packed Min/Max operations
        int dstIdx = insn.op[0].reg - x86::MM0;
        bool isMin = (insn.type == x86::InsnType::Pminub || insn.type == x86::InsnType::Pminsw);
        bool isByte = (insn.type == x86::InsnType::Pminub || insn.type == x86::InsnType::Pmaxub);
        
        int elemCount = isByte ? 8 : 4;
        const char* elemType = isByte ? "u8" : "s16";
        const char* intType = isByte ? "uint8_t" : "int16_t";
        const char* cmpOp = isMin ? "<" : ">";
        
        if (insn.op[1].type == x86::OpType::Reg && insn.op[1].reg >= x86::MM0 && insn.op[1].reg <= x86::MM7)
        {
            int srcIdx = insn.op[1].reg - x86::MM0;
            println("\t{{");
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] {} ctx.mm[{}].{}[i]) ? ctx.mm[{}].{}[i] : ctx.mm[{}].{}[i];", 
                    dstIdx, elemType, dstIdx, elemType, cmpOp, srcIdx, elemType, dstIdx, elemType, srcIdx, elemType);
            println("\t}}");
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; {} elem[{}]; }} src;", intType, elemCount);
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            println("\t\tfor (int i = 0; i < {}; i++)", elemCount);
            println("\t\t\tctx.mm[{}].{}[i] = (ctx.mm[{}].{}[i] {} src.elem[i]) ? ctx.mm[{}].{}[i] : src.elem[i];", 
                    dstIdx, elemType, dstIdx, elemType, cmpOp, dstIdx, elemType);
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Movntq:
    {
        // Non-temporal store - store to memory bypassing cache
        // For recompilation purposes, treat as regular store
        int srcIdx = insn.op[1].reg - x86::MM0;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\tX86_STORE_U64({}, ctx.mm[{}].u64);", addr, srcIdx);
        break;
    }

    case x86::InsnType::Movntps:
    {
        // MOVNTPS m128, xmm - Non-temporal store of packed single
        // For recompilation, treat as regular store
        int srcIdx = insn.op[1].reg - x86::XMM0;
        std::string addr = FormatMemoryAddress(insn.op[0], localVariables);
        println("\t_mm_storeu_ps(reinterpret_cast<float*>(base + ({})), ctx.xmm[{}].ps);", addr, srcIdx);
        break;
    }

    case x86::InsnType::Prefetch:
        // Prefetch hint - can be ignored for recompilation
        println("\t// Prefetch hint (ignored)");
        break;

    case x86::InsnType::Bswap:
    {
        // BSWAP r32 - Byte swap a 32-bit register
        std::string reg = FormatOperand(insn.op[0], 4, localVariables);
        println("\t{} = x86_bswap32({});", reg, reg);
        break;
    }

    case x86::InsnType::Pushfd:
        // PUSHF/PUSHFD - Push EFLAGS onto stack
        println("\tctx.esp.u32 -= 4;");
        println("\tX86_STORE_U32(ctx.esp.u32, ctx.eflags);");
        break;

    case x86::InsnType::Popfd:
        // POPF/POPFD - Pop EFLAGS from stack
        println("\tctx.eflags = X86_LOAD_U32(ctx.esp.u32);");
        println("\tctx.esp.u32 += 4;");
        break;

    case x86::InsnType::Les:
    {
        // LES reg, m16:32 - Load far pointer (32-bit offset into reg, 16-bit segment into ES)
        std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
        std::string dst = FormatOperand(insn.op[0], 4, localVariables);
        println("\t{} = X86_LOAD_U32({});", dst, addr);
        println("\tctx.es = X86_LOAD_U16({} + 4);", addr);
        break;
    }
    
    case x86::InsnType::Lds:
    {
        // LDS reg, m16:32 - Load far pointer (32-bit offset into reg, 16-bit segment into DS)
        std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
        std::string dst = FormatOperand(insn.op[0], 4, localVariables);
        println("\t{} = X86_LOAD_U32({});", dst, addr);
        println("\tctx.ds = X86_LOAD_U16({} + 4);", addr);
        break;
    }
    
    case x86::InsnType::Lss:
    {
        // LSS reg, m16:32 - Load far pointer (32-bit offset into reg, 16-bit segment into SS)
        std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
        std::string dst = FormatOperand(insn.op[0], 4, localVariables);
        println("\t{} = X86_LOAD_U32({});", dst, addr);
        println("\tctx.ss = X86_LOAD_U16({} + 4);", addr);
        break;
    }
    
    case x86::InsnType::Lfs:
    {
        // LFS reg, m16:32 - Load far pointer (32-bit offset into reg, 16-bit segment into FS)
        std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
        std::string dst = FormatOperand(insn.op[0], 4, localVariables);
        println("\t{} = X86_LOAD_U32({});", dst, addr);
        println("\tctx.fs = X86_LOAD_U16({} + 4);", addr);
        break;
    }
    
    case x86::InsnType::Lgs:
    {
        // LGS reg, m16:32 - Load far pointer (32-bit offset into reg, 16-bit segment into GS)
        std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
        std::string dst = FormatOperand(insn.op[0], 4, localVariables);
        println("\t{} = X86_LOAD_U32({});", dst, addr);
        println("\tctx.gs = X86_LOAD_U16({} + 4);", addr);
        break;
    }

    case x86::InsnType::Arpl:
        // ARPL - Adjust RPL field (protected mode instruction)
        println("\t// ARPL - protected mode instruction, ignored");
        break;

    case x86::InsnType::Salc:
        // SALC - Set AL from Carry (undocumented but widely used)
        // AL = CF ? 0xFF : 0x00
        println("\tctx.eax.u8[0] = (ctx.eflags & 1) ? 0xFF : 0x00;");
        break;

    case x86::InsnType::Int1:
        // INT1/ICEBP - Single-step interrupt
        println("\t// INT1 - debug interrupt");
        break;

    case x86::InsnType::Ud2:
        // UD2 - Undefined instruction (intentional trap)
        println("\t// UD2 - intentional undefined instruction trap");
        break;

    case x86::InsnType::Cmpxchg:
    {
        // CMPXCHG r/m32, r32 - Compare and Exchange
        // if (EAX == dst) { ZF=1; dst = src; } else { ZF=0; EAX = dst; }
        std::string dst = FormatOperand(insn.op[0], 4, localVariables);
        std::string src = FormatOperandRead(insn.op[1], 4, localVariables);
        println("\t{{");
        println("\t\tuint32_t temp = {};", dst);
        println("\t\tif (ctx.eax.u32 == temp) {{");
        println("\t\t\t{} = {};", dst, src);
        println("\t\t\tctx.eflags |= 0x40; // ZF=1");
        println("\t\t}} else {{");
        println("\t\t\tctx.eax.u32 = temp;");
        println("\t\t\tctx.eflags &= ~0x40; // ZF=0");
        println("\t\t}}");
        println("\t}}");
        break;
    }

    case x86::InsnType::Xadd:
    {
        // XADD r/m32, r32 - Exchange and Add
        // temp = dst + src; src = dst; dst = temp;
        std::string dst = FormatOperand(insn.op[0], 4, localVariables);
        std::string src = FormatOperand(insn.op[1], 4, localVariables);
        println("\t{{");
        println("\t\tuint32_t temp = {} + {};", dst, src);
        println("\t\t{} = {};", src, dst);
        println("\t\t{} = temp;", dst);
        println("\t}}");
        break;
    }

    case x86::InsnType::Cvtps2pi:
    case x86::InsnType::Cvttps2pi:
    {
        // CVTPS2PI/CVTTPS2PI mm, xmm/m64 - Convert packed single to packed dword
        int dstIdx = insn.op[0].reg - x86::MM0;
        if (insn.op[1].type == x86::OpType::Reg)
        {
            int srcIdx = insn.op[1].reg - x86::XMM0;
            if (insn.type == x86::InsnType::Cvttps2pi) {
                println("\tctx.mm[{}].s32[0] = static_cast<int32_t>(ctx.xmm[{}].f32[0]);", dstIdx, srcIdx);
                println("\tctx.mm[{}].s32[1] = static_cast<int32_t>(ctx.xmm[{}].f32[1]);", dstIdx, srcIdx);
            } else {
                println("\tctx.mm[{}].s32[0] = static_cast<int32_t>(std::round(ctx.xmm[{}].f32[0]));", dstIdx, srcIdx);
                println("\tctx.mm[{}].s32[1] = static_cast<int32_t>(std::round(ctx.xmm[{}].f32[1]));", dstIdx, srcIdx);
            }
        }
        else
        {
            std::string addr = FormatMemoryAddress(insn.op[1], localVariables);
            println("\t{{");
            println("\t\tunion {{ uint64_t u64; float f32[2]; }} src;");
            println("\t\tsrc.u64 = X86_LOAD_U64({});", addr);
            if (insn.type == x86::InsnType::Cvttps2pi) {
                println("\t\tctx.mm[{}].s32[0] = static_cast<int32_t>(src.f32[0]);", dstIdx);
                println("\t\tctx.mm[{}].s32[1] = static_cast<int32_t>(src.f32[1]);", dstIdx);
            } else {
                println("\t\tctx.mm[{}].s32[0] = static_cast<int32_t>(std::round(src.f32[0]));", dstIdx);
                println("\t\tctx.mm[{}].s32[1] = static_cast<int32_t>(std::round(src.f32[1]));", dstIdx);
            }
            println("\t}}");
        }
        break;
    }

    case x86::InsnType::Cvtpd2pi:
    case x86::InsnType::Cvttpd2pi:
        // These require 66 prefix handling, stub for now
        println("\t// CVT(T)PD2PI - conversion stub");
        break;

    case x86::InsnType::Lar:
        // LAR - Load Access Rights (system instruction)
        println("\t// LAR - system instruction, requires privilege");
        break;

    case x86::InsnType::Sldt:
    case x86::InsnType::Str:
    case x86::InsnType::Lldt:
    case x86::InsnType::Ltr:
    case x86::InsnType::Verr:
    case x86::InsnType::Verw:
    case x86::InsnType::Sgdt:
    case x86::InsnType::Sidt:
    case x86::InsnType::Lgdt:
    case x86::InsnType::Lidt:
    case x86::InsnType::Smsw:
    case x86::InsnType::Lmsw:
    case x86::InsnType::Invlpg:
    case x86::InsnType::Clts:
        // System table/verification/control instructions
        println("\t// System instruction - requires privilege/emulation");
        break;

    case x86::InsnType::Jmpf:
    {
        // Far jump - in flat memory model, just jump to the offset
        // The segment selector is stored but not used for address calculation
        uint32_t offset = insn.op[0].imm;
        uint16_t segment = static_cast<uint16_t>(insn.op[1].imm);
        println("\tctx.cs = 0x{:X};", segment);
        println("\tgoto loc_{:X}; // Far JMP to {:04X}:{:08X}", offset, segment, offset);
        break;
    }

    case x86::InsnType::PopSeg:
        // Segment register operations - rarely used in modern code
        println("\t// Segment register operation - ignored");
        break;

    case x86::InsnType::Ldmxcsr:
        // Load MXCSR register - controls SSE rounding/exceptions
        println("\t// LDMXCSR - SSE control register load");
        break;

    case x86::InsnType::Stmxcsr:
        // Store MXCSR register
        println("\t// STMXCSR - SSE control register store");
        break;

    case x86::InsnType::Fxsave:
    case x86::InsnType::Fxrstor:
        // FPU/MMX/SSE state save/restore
        println("\t// FXSAVE/FXRSTOR - FPU state save/restore");
        break;

    case x86::InsnType::Lfence:
    case x86::InsnType::Mfence:
    case x86::InsnType::Sfence:
        // Memory fence instructions - usually no-op for recompilation
        println("\t// Memory fence instruction");
        break;

    case x86::InsnType::Bt:
        // Bit Test - sets CF to the bit value
        {
            localVariables.eflags = true;
            auto src = FormatOperandRead(insn.op[0], 4, localVariables);
            auto bit = FormatOperandRead(insn.op[1], 4, localVariables);
            println("\tctx.eflags.cf = ({} >> ({} & 31)) & 1;", src, bit);
        }
        break;

    case x86::InsnType::Bts:
        // Bit Test and Set - sets CF to original bit, then sets the bit
        {
            localVariables.eflags = true;
            auto dst = FormatOperandRead(insn.op[0], 4, localVariables);
            auto bit = FormatOperandRead(insn.op[1], 4, localVariables);
            println("\t{{");
            println("\t\tuint32_t bitPos = {} & 31;", bit);
            println("\t\tctx.eflags.cf = ({} >> bitPos) & 1;", dst);
            println("\t\t{};", FormatOperandWrite(insn.op[0], fmt::format("{} | (1u << bitPos)", dst), 4, localVariables));
            println("\t}}");
        }
        break;

    case x86::InsnType::Btr:
        // Bit Test and Reset - sets CF to original bit, then clears the bit
        {
            localVariables.eflags = true;
            auto dst = FormatOperandRead(insn.op[0], 4, localVariables);
            auto bit = FormatOperandRead(insn.op[1], 4, localVariables);
            println("\t{{");
            println("\t\tuint32_t bitPos = {} & 31;", bit);
            println("\t\tctx.eflags.cf = ({} >> bitPos) & 1;", dst);
            println("\t\t{};", FormatOperandWrite(insn.op[0], fmt::format("{} & ~(1u << bitPos)", dst), 4, localVariables));
            println("\t}}");
        }
        break;

    case x86::InsnType::Btc:
        // Bit Test and Complement - sets CF to original bit, then toggles the bit
        {
            localVariables.eflags = true;
            auto dst = FormatOperandRead(insn.op[0], 4, localVariables);
            auto bit = FormatOperandRead(insn.op[1], 4, localVariables);
            println("\t{{");
            println("\t\tuint32_t bitPos = {} & 31;", bit);
            println("\t\tctx.eflags.cf = ({} >> bitPos) & 1;", dst);
            println("\t\t{};", FormatOperandWrite(insn.op[0], fmt::format("{} ^ (1u << bitPos)", dst), 4, localVariables));
            println("\t}}");
        }
        break;

    case x86::InsnType::Cvtpi2ps:
        // Convert packed dword integers (MMX) to packed single-precision floats
        {
            auto src = FormatOperandRead(insn.op[1], 8, localVariables);
            auto dstReg = GetXmmRegName(insn.op[0].reg);
            println("\tctx.{}.f32[0] = static_cast<float>(reinterpret_cast<int32_t*>(&{})[0]);", dstReg, src);
            println("\tctx.{}.f32[1] = static_cast<float>(reinterpret_cast<int32_t*>(&{})[1]);", dstReg, src);
        }
        break;

    case x86::InsnType::Cvtpi2pd:
        // Convert packed dword integers (MMX) to packed double-precision floats
        {
            auto src = FormatOperandRead(insn.op[1], 8, localVariables);
            auto dstReg = GetXmmRegName(insn.op[0].reg);
            println("\tctx.{}.f64[0] = static_cast<double>(reinterpret_cast<int32_t*>(&{})[0]);", dstReg, src);
            println("\tctx.{}.f64[1] = static_cast<double>(reinterpret_cast<int32_t*>(&{})[1]);", dstReg, src);
        }
        break;

    case x86::InsnType::Pinsrw:
        // Insert word into MMX register at position specified by imm8
        {
            auto src = FormatOperandRead(insn.op[1], 4, localVariables);
            uint8_t idx = static_cast<uint8_t>(insn.op[2].imm) & 3;  // Only 2 bits for MMX
            auto dstReg = GetMmxRegName(insn.op[0].reg);
            println("\treinterpret_cast<uint16_t*>(&ctx.{})[{}] = static_cast<uint16_t>({});", dstReg, idx, src);
        }
        break;

    case x86::InsnType::Pextrw:
        // Extract word from MMX register
        {
            auto srcReg = GetMmxRegName(insn.op[1].reg);
            uint8_t idx = static_cast<uint8_t>(insn.op[2].imm) & 3;
            println("\t{};", FormatOperandWrite(insn.op[0], 
                fmt::format("reinterpret_cast<uint16_t*>(&ctx.{})[{}]", srcReg, idx), 4, localVariables));
        }
        break;

    case x86::InsnType::Pmovmskb:
        // Move byte mask from MMX to GPR
        {
            auto srcReg = GetMmxRegName(insn.op[1].reg);
            println("\t{{");
            println("\t\tuint32_t mask = 0;");
            println("\t\tfor (int i = 0; i < 8; i++) {{ mask |= ((reinterpret_cast<uint8_t*>(&ctx.{})[i] >> 7) << i); }}", srcReg);
            println("\t\t{};", FormatOperandWrite(insn.op[0], "mask", 4, localVariables));
            println("\t}}");
        }
        break;

    case x86::InsnType::Amd3dnow:
        // AMD 3DNow! instructions - deprecated, treat as no-op or stub
        println("\t// 3DNow! instruction (AMD legacy) - not implemented");
        break;

    case x86::InsnType::Cpuid:
        // CPUID - return fake CPU info or stub
        localVariables.eax = true;
        localVariables.ebx = true;
        localVariables.ecx = true;
        localVariables.edx = true;
        println("\t// CPUID - returning stub values");
        println("\tctx.eax.u32 = 0; ctx.ebx.u32 = 0; ctx.ecx.u32 = 0; ctx.edx.u32 = 0;");
        break;

    case x86::InsnType::Wbinvd:
    case x86::InsnType::Invd:
        // Cache invalidation - no-op in recompiled code
        println("\t// Cache invalidation (privileged) - ignored");
        break;

    case x86::InsnType::Sysret:
        // SYSRET - return from fast system call (privileged)
        println("\t// SYSRET (privileged) - should not appear in user code");
        break;

    case x86::InsnType::Haddps:
        // Horizontal add packed single-precision floats
        {
            auto dst = GetXmmRegName(insn.op[0].reg);
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            println("\tctx.{}.m128 = simde_mm_hadd_ps(ctx.{}.m128, {});", dst, dst, src);
        }
        break;

    case x86::InsnType::Haddpd:
        // Horizontal add packed double-precision floats
        {
            auto dst = GetXmmRegName(insn.op[0].reg);
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            println("\tctx.{}.m128d = simde_mm_hadd_pd(ctx.{}.m128d, {});", dst, dst, src);
        }
        break;

    case x86::InsnType::Hsubps:
        // Horizontal subtract packed single-precision floats
        {
            auto dst = GetXmmRegName(insn.op[0].reg);
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            println("\tctx.{}.m128 = simde_mm_hsub_ps(ctx.{}.m128, {});", dst, dst, src);
        }
        break;

    case x86::InsnType::Hsubpd:
        // Horizontal subtract packed double-precision floats
        {
            auto dst = GetXmmRegName(insn.op[0].reg);
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            println("\tctx.{}.m128d = simde_mm_hsub_pd(ctx.{}.m128d, {});", dst, dst, src);
        }
        break;

    case x86::InsnType::Cmppd:
        // Compare packed double-precision floats with predicate
        {
            auto dst = GetXmmRegName(insn.op[0].reg);
            auto src = FormatXmmOperandRead(insn.op[1], localVariables);
            uint8_t predicate = static_cast<uint8_t>(insn.op[2].imm);
            println("\tctx.{}.m128d = simde_mm_cmp_pd(ctx.{}.m128d, {}, {});", dst, dst, src, predicate);
        }
        break;

    case x86::InsnType::Movdqu:
        // Move unaligned double quadword (128-bit XMM)
        {
            if (insn.op[0].type == x86::OpType::Reg)
            {
                // Load: xmm <- mem or xmm <- xmm
                auto dst = GetXmmRegName(insn.op[0].reg);
                auto src = FormatXmmOperandRead(insn.op[1], localVariables);
                println("\tctx.{}.m128i = {};", dst, src);
            }
            else
            {
                // Store: mem <- xmm
                auto addr = FormatMemoryAddress(insn.op[0], localVariables);
                auto src = GetXmmRegName(insn.op[1].reg);
                println("\tX86_STORE_U64({}, ctx.{}.u64[0]);", addr, src);
                println("\tX86_STORE_U64({} + 8, ctx.{}.u64[1]);", addr, src);
            }
        }
        break;

    case x86::InsnType::Movq_sse:
        // Move quadword (64-bit) SSE version
        {
            auto dst = GetXmmRegName(insn.op[0].reg);
            if (insn.op[1].type == x86::OpType::Reg)
            {
                auto src = GetXmmRegName(insn.op[1].reg);
                println("\tctx.{}.u64[0] = ctx.{}.u64[0];", dst, src);
                println("\tctx.{}.u64[1] = 0;", dst);
            }
            else
            {
                auto addr = FormatMemoryAddress(insn.op[1], localVariables);
                println("\tctx.{}.u64[0] = X86_LOAD_U64({});", dst, addr);
                println("\tctx.{}.u64[1] = 0;", dst);
            }
        }
        break;

    case x86::InsnType::Invalid:
        // Invalid/undefined opcode - likely garbage data interpreted as code
        println("\t// Invalid opcode (undefined instruction encoding)");
        break;

    case x86::InsnType::Unknown:
    default:
        println("\t// TODO: Unhandled instruction");
        return false;
    }

    return true;
}

X86Recompiler::ControlFlowResult X86Recompiler::AnalyzeControlFlow(const Function& fn, const Section* section)
{
    std::vector<X86BasicBlock> blocks;
    std::set<uint32_t> blockStarts;
    std::set<uint32_t> visited;
    std::vector<uint32_t> workList;

    // Debug: Check if this function is in TOML config
    auto tomlIt = config.functions.find(fn.base);
    if (tomlIt != config.functions.end())
    {
        fmt::println("DEBUG AnalyzeControlFlow: fn.base=0x{:X}, fn.size=0x{:X} (from param), TOML size=0x{:X}", 
            fn.base, fn.size, tomlIt->second);
        if (fn.size != tomlIt->second)
        {
            fmt::println("WARNING: fn.size mismatch! Using TOML size.");
        }
    }

    // Check for function chunks
    auto chunksIt = config.functionChunks.find(fn.base);
    bool hasChunks = (chunksIt != config.functionChunks.end() && !chunksIt->second.empty());
    
    // Build a set of addresses that belong to this function (including chunks)
    std::set<std::pair<uint32_t, uint32_t>> functionRanges;  // {start, end} pairs
    functionRanges.insert({fn.base, fn.base + fn.size});
    
    if (hasChunks)
    {
        fmt::println("Function 0x{:X} has {} chunks:", fn.base, chunksIt->second.size());
        for (const auto& [chunkAddr, chunkSize] : chunksIt->second)
        {
            fmt::println("  Chunk: 0x{:X} - 0x{:X} (size 0x{:X})", chunkAddr, chunkAddr + chunkSize, chunkSize);
            functionRanges.insert({chunkAddr, chunkAddr + chunkSize});
        }
    }
    
    // Helper to check if an address belongs to this function (main body or chunks)
    auto isInFunctionRange = [&](uint32_t addr) -> bool {
        for (const auto& [start, end] : functionRanges)
        {
            if (addr >= start && addr < end)
                return true;
        }
        return false;
    };
    
    // Helper to get section for an address
    auto getSectionForAddress = [&](uint32_t addr) -> const Section* {
        for (const auto& sec : image.sections)
        {
            if (addr >= sec.base && addr < sec.base + sec.size)
                return &sec;
        }
        return nullptr;
    };

    // Track effective bounds - may extend beyond fn.base/fn.size due to backward jumps
    uint32_t effectiveBase = fn.base;
    uint32_t effectiveEnd = fn.base + fn.size;

    // Function entry is a block start
    blockStarts.insert(fn.base);
    workList.push_back(fn.base);
    
    // Add chunk entry points to worklist
    if (hasChunks)
    {
        for (const auto& [chunkAddr, chunkSize] : chunksIt->second)
        {
            blockStarts.insert(chunkAddr);
            workList.push_back(chunkAddr);
        }
    }

    // Helper to check if an address is within section bounds (any section)
    auto isInSection = [&](uint32_t addr) {
        return getSectionForAddress(addr) != nullptr;
    };

    // First pass: identify all block start addresses
    while (!workList.empty())
    {
        uint32_t addr = workList.back();
        workList.pop_back();

        // Skip if already visited
        if (visited.count(addr))
            continue;
        
        // Get section for this address (may be different for chunks)
        const Section* addrSection = getSectionForAddress(addr);
        if (!addrSection)
            continue;

        // Check if this is outside current effective bounds and not a chunk
        if (addr < effectiveBase || addr >= effectiveEnd)
        {
            // Allow if it's in a function chunk range
            if (!isInFunctionRange(addr))
            {
                // For addresses outside fn bounds, only follow if not another function's entry
                if (functionEntryPoints.count(addr) && addr != fn.base)
                    continue;  // Don't cross into other functions
            }
            
            // Extend effective bounds (note: chunks may be non-contiguous, so we track them separately)
            if (addr < effectiveBase && !hasChunks)
                effectiveBase = addr;
        }

        visited.insert(addr);

        const uint8_t* p = addrSection->data + (addr - addrSection->base);
        const uint8_t* sectionEnd = addrSection->data + addrSection->size;
        
        while (p < sectionEnd)
        {
            uint32_t currentAddr = addrSection->base + (p - addrSection->data);
            
            // Always stop at other function entry points - unless it's a chunk entry
            if (currentAddr != fn.base && functionEntryPoints.count(currentAddr) && !isInFunctionRange(currentAddr))
                break;
            
            // Stop if we've gone past the effective end and hit visited code (for non-chunk code)
            if (!isInFunctionRange(currentAddr) && currentAddr >= effectiveEnd && visited.count(currentAddr))
                break;

            x86::Insn insn;
            int len = x86::Disassemble(p, sectionEnd - p, currentAddr, insn);
            if (len <= 0) break;

            // Update effective end if we're past the original bounds but don't cross function boundaries
            if (currentAddr + len > effectiveEnd && !hasChunks)
            {
                // Check if extending would cross into another function
                bool wouldCrossFunction = false;
                for (uint32_t ep : functionEntryPoints)
                {
                    if (ep != fn.base && ep > effectiveEnd && ep < currentAddr + len)
                    {
                        wouldCrossFunction = true;
                        break;
                    }
                }
                if (!wouldCrossFunction)
                {
                    effectiveEnd = currentAddr + len;
                }
            }

            bool isTerminator = false;

            switch (insn.type)
            {
            case x86::InsnType::Ret:
                isTerminator = true;
                break;

            case x86::InsnType::Jmp:
                isTerminator = true;
                if (insn.is_branch_relative)
                {
                    // Allow jumps within function body or to function chunks
                    bool isWithinFunction = isInFunctionRange(insn.branch_target);
                    bool isOtherFunction = functionEntryPoints.count(insn.branch_target) && 
                                           insn.branch_target != fn.base && 
                                           !isWithinFunction;
                    
                    if (!isOtherFunction && isInSection(insn.branch_target))
                    {
                        blockStarts.insert(insn.branch_target);
                        workList.push_back(insn.branch_target);
                    }
                }
                break;

            case x86::InsnType::JmpIndirect:
                isTerminator = true;
                // Check if this is a switch table jump - add all labels as block starts
                {
                    auto stIt = config.switchTables.find(currentAddr);
                    if (stIt != config.switchTables.end())
                    {
                        for (uint32_t label : stIt->second.labels)
                        {
                            bool isWithinFunction = isInFunctionRange(label);
                            bool isOtherFunction = functionEntryPoints.count(label) && 
                                                   label != fn.base && 
                                                   !isWithinFunction;
                            if (isInSection(label) && !isOtherFunction)
                            {
                                blockStarts.insert(label);
                                workList.push_back(label);
                            }
                        }
                        if (stIt->second.defaultLabel != 0 && isInSection(stIt->second.defaultLabel))
                        {
                            bool isWithinFunction = isInFunctionRange(stIt->second.defaultLabel);
                            bool isOtherFunction = functionEntryPoints.count(stIt->second.defaultLabel) && 
                                                   stIt->second.defaultLabel != fn.base && 
                                                   !isWithinFunction;
                            if (!isOtherFunction)
                            {
                                blockStarts.insert(stIt->second.defaultLabel);
                                workList.push_back(stIt->second.defaultLabel);
                            }
                        }
                    }
                }
                break;

            case x86::InsnType::Jcc:
                // Conditional branch: both targets are block starts
                if (isInSection(insn.branch_target))
                {
                    // Allow jumps within function body or to function chunks
                    bool isWithinFunction = isInFunctionRange(insn.branch_target);
                    bool isOtherFunction = functionEntryPoints.count(insn.branch_target) && 
                                           insn.branch_target != fn.base && 
                                           !isWithinFunction;
                    
                    if (!isOtherFunction)
                    {
                        blockStarts.insert(insn.branch_target);
                        workList.push_back(insn.branch_target);
                    }
                }
                // Fall-through is also a block start
                {
                    uint32_t fallThrough = currentAddr + len;
                    // Allow fall-through within function or to chunks
                    bool isWithinFunction = isInFunctionRange(fallThrough);
                    bool isOtherFunction = functionEntryPoints.count(fallThrough) && 
                                           fallThrough != fn.base && 
                                           !isWithinFunction;
                    
                    if (isInSection(fallThrough) && !isOtherFunction)
                    {
                        blockStarts.insert(fallThrough);
                        workList.push_back(fallThrough);
                    }
                }
                isTerminator = true;
                break;

            case x86::InsnType::Call:
                // Calls don't terminate blocks, but could throw
                break;

            default:
                break;
            }

            p += len;

            if (isTerminator)
                break;

            // Check if we've hit another block start
            uint32_t nextAddr = addrSection->base + (p - addrSection->data);
            if (blockStarts.count(nextAddr))
                break;
        }
    }

    // Force analysis of entire TOML-specified range to catch SEH handlers
    // Linearly scan and add any unvisited instruction addresses
    {
        // Use TOML size if available, otherwise use function's detected size
        uint32_t scanSize = fn.size;
        if (tomlIt != config.functions.end())
        {
            scanSize = tomlIt->second;
        }
        
        const uint8_t* p = section->data + (fn.base - section->base);
        const uint8_t* sectionEnd = section->data + section->size;
        const uint8_t* rangeEnd = section->data + (fn.base + scanSize - section->base);
        
        std::vector<uint32_t> newBlocks;
        while (p < rangeEnd && p < sectionEnd)
        {
            uint32_t addr = section->base + (p - section->data);
            
            // Skip if this address is a known function entry point (and not our function)
            if (addr != fn.base && functionEntryPoints.count(addr))
            {
                // Stop scanning - we've hit another function
                break;
            }
            
            // Try to decode instruction
            x86::Insn insn;
            int len = x86::Disassemble(p, sectionEnd - p, addr, insn);
            if (len > 0)
            {
                if (!visited.count(addr))
                {
                    // Unvisited code - add to newBlocks for worklist processing
                    blockStarts.insert(addr);
                    newBlocks.push_back(addr);
                }
                p += len;
            }
            else
            {
                p++; // Skip bad byte
            }
        }
        
        if (!newBlocks.empty())
        {
            fmt::println("Gap scan found {} unreachable block starts in function 0x{:X}", newBlocks.size(), fn.base);
            
            // Process newly discovered blocks through worklist to analyze control flow
            for (uint32_t blockAddr : newBlocks)
            {
                workList.push_back(blockAddr);
            }
            
            // Continue worklist processing for the newly added blocks
            while (!workList.empty())
            {
                uint32_t addr = workList.back();
                workList.pop_back();

                if (visited.count(addr) || !isInSection(addr))
                    continue;
                
                // Don't process addresses that are other functions' entry points
                if (addr != fn.base && functionEntryPoints.count(addr))
                    continue;

                visited.insert(addr);
                blockStarts.insert(addr);

                const uint8_t* p = section->data + (addr - section->base);
                const uint8_t* sectionEnd = section->data + section->size;

                while (p < sectionEnd)
                {
                    uint32_t currentAddr = section->base + (p - section->data);
                    
                    // Stop if we hit another function's entry point
                    if (currentAddr != fn.base && functionEntryPoints.count(currentAddr))
                        break;
                    
                    if (currentAddr > effectiveEnd)
                        effectiveEnd = currentAddr;

                    x86::Insn insn;
                    int len = x86::Disassemble(p, sectionEnd - p, currentAddr, insn);
                    if (len <= 0) break;

                    bool isTerminator = false;

                    switch (insn.type)
                    {
                    case x86::InsnType::Ret:
                        isTerminator = true;
                        break;

                    case x86::InsnType::Jmp:
                        isTerminator = true;
                        if (insn.is_branch_relative && isInSection(insn.branch_target))
                        {
                            bool targetInFunction = (insn.branch_target >= fn.base && insn.branch_target < fn.base + fn.size);
                            if (targetInFunction)
                            {
                                blockStarts.insert(insn.branch_target);
                                workList.push_back(insn.branch_target);
                            }
                        }
                        break;

                    case x86::InsnType::Jcc:
                        isTerminator = true;
                        if (isInSection(insn.branch_target))
                        {
                            bool targetInFunction = (insn.branch_target >= fn.base && insn.branch_target < fn.base + fn.size);
                            if (targetInFunction)
                            {
                                blockStarts.insert(insn.branch_target);
                                workList.push_back(insn.branch_target);
                            }
                        }
                        // Fall-through
                        {
                            uint32_t fallThrough = currentAddr + len;
                            bool fallThroughInFunction = (fallThrough >= fn.base && fallThrough < fn.base + fn.size);
                            if (isInSection(fallThrough) && fallThroughInFunction)
                            {
                                blockStarts.insert(fallThrough);
                                workList.push_back(fallThrough);
                            }
                        }
                        break;

                    case x86::InsnType::Call:
                        // Calls don't terminate blocks
                        break;

                    default:
                        break;
                    }

                    p += len;

                    if (isTerminator)
                        break;

                    // Check if we've hit another block start
                    uint32_t nextAddr = section->base + (p - section->data);
                    if (blockStarts.count(nextAddr))
                        break;
                }
            }
            
            fmt::println("Completed worklist processing for unreachable blocks");
            
            // Debug: Show last few block starts to see if they cover the TOML range
            std::vector<uint32_t> allStarts(blockStarts.begin(), blockStarts.end());
            std::sort(allStarts.begin(), allStarts.end());
            fmt::println("Total blockStarts: {}, last 5 addresses:", allStarts.size());
            for (size_t i = allStarts.size() > 5 ? allStarts.size() - 5 : 0; i < allStarts.size(); i++)
            {
                fmt::println("  0x{:X}", allStarts[i]);
            }
            fmt::println("TOML-specified end: 0x{:X}, effectiveEnd: 0x{:X}", fn.base + scanSize, effectiveEnd);
        }
        
        // Update effectiveEnd to cover the full TOML range, but clamp to next function entry
        if (fn.base + scanSize > effectiveEnd)
        {
            uint32_t proposedEnd = fn.base + scanSize;
            
            // Find the earliest function entry point that's after our base and before the proposed end
            for (uint32_t entryPoint : functionEntryPoints)
            {
                if (entryPoint > fn.base && entryPoint < proposedEnd)
                {
                    proposedEnd = entryPoint;
                }
            }
            
            if (proposedEnd > effectiveEnd)
            {
                effectiveEnd = proposedEnd;
            }
        }
    }
    
    // Second pass: build basic blocks using effective bounds
    std::vector<uint32_t> sortedStarts(blockStarts.begin(), blockStarts.end());
    std::sort(sortedStarts.begin(), sortedStarts.end());

    for (size_t i = 0; i < sortedStarts.size(); i++)
    {
        X86BasicBlock block;
        block.start = sortedStarts[i];
        
        // Get section for this block (may differ for chunks)
        const Section* blockSection = getSectionForAddress(block.start);
        if (!blockSection)
        {
            fmt::println("WARNING: Block at 0x{:X} not in any section, skipping", block.start);
            continue;
        }
        
        // Block ends at next block start, chunk boundary, or section end
        uint32_t blockEnd = blockSection->base + blockSection->size;  // Section end as default
        
        // Check next block start
        if (i + 1 < sortedStarts.size())
        {
            uint32_t nextStart = sortedStarts[i + 1];
            // Only use next start if it's in the same section
            if (getSectionForAddress(nextStart) == blockSection && nextStart < blockEnd)
            {
                blockEnd = nextStart;
            }
        }
        
        // For non-chunk blocks, also consider effectiveEnd
        if (!hasChunks && effectiveEnd < blockEnd)
        {
            blockEnd = effectiveEnd;
        }

        const uint8_t* p = blockSection->data + (block.start - blockSection->base);
        const uint8_t* pEnd = blockSection->data + (blockEnd - blockSection->base);
        uint32_t addr = block.start;

        // Find the actual terminator
        while (p < pEnd)
        {
            x86::Insn insn;
            int len = x86::Disassemble(p, pEnd - p, addr, insn);
            if (len <= 0) break;

            uint32_t nextAddr = addr + len;

            switch (insn.type)
            {
            case x86::InsnType::Ret:
                block.end = nextAddr;
                block.endsWithRet = true;
                block.fallsThrough = false;
                break;

            case x86::InsnType::Jmp:
                block.end = nextAddr;
                block.endsWithJmp = true;
                block.fallsThrough = false;
                if (insn.is_branch_relative)
                    block.jumpTarget = insn.branch_target;
                break;

            case x86::InsnType::JmpIndirect:
                block.end = nextAddr;
                block.endsWithJmp = true;
                block.fallsThrough = false;
                break;

            case x86::InsnType::Jcc:
                block.end = nextAddr;
                block.fallsThrough = true;  // Falls through if condition is false
                // Allow targets within function body or chunks
                if (isInFunctionRange(insn.branch_target) || 
                    (insn.branch_target >= effectiveBase && insn.branch_target < effectiveEnd))
                {
                    block.condTargets.push_back(insn.branch_target);
                }
                break;

            case x86::InsnType::Int3:
                // INT3 at the end of a block is typically padding after a noreturn call
                block.end = nextAddr;
                block.endsWithJmp = true;  // Treat as terminator (unreachable)
                block.fallsThrough = false;
                break;

            default:
                break;
            }

            p += len;
            addr = nextAddr;

            // If we hit a terminator, stop
            if (block.end != 0)
                break;
        }

        // If no terminator found, block falls through to next
        if (block.end == 0)
        {
            block.end = blockEnd;
            // Only falls through if there's a next block starting at blockEnd
            block.fallsThrough = blockStarts.count(blockEnd) > 0;
        }

        blocks.push_back(block);
    }

    return ControlFlowResult{std::move(blocks), effectiveBase, effectiveEnd, hasChunks, functionRanges};
}

std::set<uint32_t> X86Recompiler::CollectLabelAddresses(const Function& fn, const Section* section,
                                                         const std::vector<X86BasicBlock>& blocks,
                                                         uint32_t effectiveBase, uint32_t effectiveEnd)
{
    std::set<uint32_t> labels;

    // All block starts (except first) need labels
    for (size_t i = 1; i < blocks.size(); i++)
    {
        labels.insert(blocks[i].start);
    }

    // All conditional and unconditional jump targets within effective function range need labels
    for (const auto& block : blocks)
    {
        if (block.jumpTarget >= effectiveBase && block.jumpTarget < effectiveEnd)
            labels.insert(block.jumpTarget);

        for (uint32_t target : block.condTargets)
        {
            if (target >= effectiveBase && target < effectiveEnd)
                labels.insert(target);
        }
    }

    return labels;
}

bool X86Recompiler::Recompile(const Function& fn)
{
    // Find function in symbol table
    auto fnSymbol = image.symbols.find(fn.base);
    if (fnSymbol == image.symbols.end())
    {
        fmt::println("ERROR: Function not found in symbol table: {:X}", fn.base);
        return false;
    }

    // Find section containing function
    const Section* fnSection = nullptr;
    for (const auto& section : image.sections)
    {
        if (fn.base >= section.base && fn.base < section.base + section.size)
        {
            fnSection = &section;
            break;
        }
    }

    if (!fnSection)
    {
        fmt::println("ERROR: Function {:X} not in any section", fn.base);
        return false;
    }

    // Analyze control flow - this may extend bounds beyond fn.base/fn.size
    auto cfResult = AnalyzeControlFlow(fn, fnSection);
    auto& blocks = cfResult.blocks;
    uint32_t effectiveBase = cfResult.effectiveBase;
    uint32_t effectiveEnd = cfResult.effectiveEnd;
    bool hasChunks = cfResult.hasChunks;
    auto& functionRanges = cfResult.functionRanges;
    
    // Helper to get section for address (needed for chunks in different sections)
    auto getSectionForAddress = [&](uint32_t addr) -> const Section* {
        for (const auto& sec : image.sections)
        {
            if (addr >= sec.base && addr < sec.base + sec.size)
                return &sec;
        }
        return nullptr;
    };
    
    // Helper to check if address is in function range (including chunks)
    auto isInFunctionRange = [&](uint32_t addr) -> bool {
        for (const auto& [start, end] : functionRanges)
        {
            if (addr >= start && addr < end)
                return true;
        }
        return false;
    };
    
    auto labels = CollectLabelAddresses(fn, fnSection, blocks, effectiveBase, effectiveEnd);
    
    // Add chunk entry points as labels if function has chunks
    if (hasChunks)
    {
        auto chunksIt = config.functionChunks.find(fn.base);
        if (chunksIt != config.functionChunks.end())
        {
            for (const auto& [chunkAddr, chunkSize] : chunksIt->second)
            {
                labels.insert(chunkAddr);
            }
        }
    }

    // Generate function header
    std::string tempOut;
    std::swap(out, tempOut);
    
    X86RecompilerLocalVariables localVariables{};

    // Generate function body - process each basic block
    bool allRecompiled = true;
    auto switchTable = config.switchTables.end();

    for (size_t blockIdx = 0; blockIdx < blocks.size(); blockIdx++)
    {
        const auto& block = blocks[blockIdx];
        
        // Get section for this block (may be different for chunks)
        const Section* blockSection = getSectionForAddress(block.start);
        if (!blockSection)
        {
            println("\t// ERROR: Block at {:X} not in any section", block.start);
            allRecompiled = false;
            continue;
        }
        
        const uint8_t* p = blockSection->data + (block.start - blockSection->base);
        const uint8_t* blockEnd = blockSection->data + (block.end - blockSection->base);
        uint32_t addr = block.start;

        while (addr < block.end && p < blockEnd)
        {
            // Check for switch table at this address
            auto st = config.switchTables.find(addr);
            if (st != config.switchTables.end())
                switchTable = st;

            // Output label if needed
            if (labels.count(addr))
            {
                println("loc_{:X}:", addr);
            }

            // Check if this address is marked as invalid (likely data)
            auto invalidIt = config.invalidAddresses.find(addr);
            if (invalidIt != config.invalidAddresses.end())
            {
                println("\t// Skipping {} bytes at {:X} (marked as invalid/data)", invalidIt->second, addr);
                p += invalidIt->second;
                addr += invalidIt->second;
                continue;
            }

            x86::Insn insn;
            int len = x86::Disassemble(p, blockEnd - p, addr, insn);
            if (len <= 0)
            {
                println("\t// ERROR: Failed to disassemble at {:X}", addr);
                p++;
                addr++;
                allRecompiled = false;
                continue;
            }

            // Check if this instruction's fall-through needs a label
            uint32_t nextAddr = addr + len;
            bool needsFallThroughLabel = labels.count(nextAddr) > 0;

            if (!RecompileInstruction(fn, addr, insn, p, switchTable, localVariables, needsFallThroughLabel, effectiveBase, effectiveEnd))
            {
                allRecompiled = false;
            }

            p += len;
            addr = nextAddr;
        }

        // Handle fall-through between blocks
        if (block.fallsThrough && blockIdx + 1 < blocks.size())
        {
            uint32_t nextBlockStart = blocks[blockIdx + 1].start;
            
            // If the next block has a label and we're falling through,
            // we might need an explicit goto if there's dead code between blocks
            if (block.end < nextBlockStart)
            {
                // There's a gap - skip over it
                println("\t// Fall through to next block");
            }
        }
    }

    // Add final return if function doesn't end with one
    // (safety net for malformed functions)
    if (!blocks.empty())
    {
        const auto& lastBlock = blocks.back();
        if (!lastBlock.endsWithRet && !lastBlock.endsWithJmp)
        {
            println("\t// WARNING: Function does not end with ret/jmp");
            println("\treturn;");
        }
    }

    println("}}");
    println("");

    // Generate function declaration with local variables
    std::swap(out, tempOut);

    println("// {:X} - {:X} ({} basic blocks)", effectiveBase, effectiveEnd, blocks.size());
    println("X86_FUNC_IMPL({}) {{", fnSymbol->name);
    println("\tX86_FUNC_PROLOGUE();");

    // Output local variable declarations if needed
    // (Currently we use ctx directly, but we could optimize to use locals)

    out += tempOut;

    return allRecompiled;
}

void X86Recompiler::Recompile(const std::filesystem::path& headerFilePath)
{
    out.reserve(10 * 1024 * 1024);

    // Generate x86_config.h
    {
        println("#pragma once");
        println("");
        println("#ifndef X86_CONFIG_H_INCLUDED");
        println("#define X86_CONFIG_H_INCLUDED");
        println("");
        
        println("#define X86_IMAGE_BASE 0x{:X}ull", image.base);
        println("#define X86_IMAGE_SIZE 0x{:X}ull", image.size);
        
        // Extract code range
        size_t codeMin = ~0ull;
        size_t codeMax = 0;
        for (auto& section : image.sections)
        {
            if (section.flags & SectionFlags_Code)
            {
                if (section.base < codeMin)
                    codeMin = section.base;
                if (section.base + section.size > codeMax)
                    codeMax = section.base + section.size;
            }
        }
        
        println("#define X86_CODE_BASE 0x{:X}ull", codeMin);
        println("#define X86_CODE_SIZE 0x{:X}ull", codeMax - codeMin);
        println("");
        println("#endif // X86_CONFIG_H_INCLUDED");
        
        SaveCurrentOutData("x86_config.h");
    }

    // Generate x86_context.h (copy from source)
    {
        println("#pragma once");
        println("");
        println("#include \"x86_config.h\"");
        println("");
        
        std::ifstream stream(headerFilePath);
        if (stream.good())
        {
            std::stringstream ss;
            ss << stream.rdbuf();
            out += ss.str();
        }
        
        SaveCurrentOutData("x86_context.h");
    }

    // Generate x86_recomp_shared.h
    {
        println("#pragma once");
        println("");
        println("#include \"x86_config.h\"");
        println("#include \"x86_context.h\"");
        println("");
        
        for (auto& symbol : image.symbols)
        {
            if (symbol.type == Symbol_Function)
                println("X86_EXTERN_FUNC({});", symbol.name);
        }
        
        SaveCurrentOutData("x86_recomp_shared.h");
    }

    // Generate x86_func_mapping.cpp
    {
        println("#include \"x86_recomp_shared.h\"");
        println("");
        println("X86FuncMapping X86FuncMappings[] = {{");
        
        for (auto& symbol : image.symbols)
        {
            if (symbol.type == Symbol_Function)
                println("\t{{ 0x{:X}, {} }},", symbol.address, symbol.name);
        }
        
        println("\t{{ 0, nullptr }}");
        println("}};");
        
        SaveCurrentOutData("x86_func_mapping.cpp");
    }

    // Generate recompiled functions
    size_t functionsRecompiled = 0;
    
    // In single function mode, check if the function exists in our list
    // If not, try to add it from the manual functions in config
    if (config.singleFunctionAddress != 0)
    {
        bool found = false;
        for (const auto& fn : functions)
        {
            if (fn.base == config.singleFunctionAddress)
            {
                found = true;
                break;
            }
        }
        
        if (!found)
        {
            fmt::println("DEBUG: Function 0x{:X} not found in analyzed functions list (total: {})", 
                        config.singleFunctionAddress, functions.size());
            fmt::println("DEBUG: config.functions map has {} entries", config.functions.size());
            
            // Check if it's in the TOML functions
            auto it = config.functions.find(config.singleFunctionAddress);
            if (it != config.functions.end())
            {
                fmt::println("Function 0x{:X} not in analyzed functions list, but found in TOML with size 0x{:X} - adding it", 
                            config.singleFunctionAddress, it->second);
                
                // Check if symbol exists, create it if it doesn't
                auto symIt = image.symbols.find(config.singleFunctionAddress);
                if (symIt == image.symbols.end())
                {
                    fmt::println("Creating symbol for function 0x{:X}", config.singleFunctionAddress);
                    Symbol sym;
                    sym.name = fmt::format("sub_{:X}", config.singleFunctionAddress);
                    sym.address = config.singleFunctionAddress;
                    sym.size = it->second;
                    sym.type = Symbol_Function;
                    image.symbols.insert(sym);
                }
                
                Function fn;
                fn.base = config.singleFunctionAddress;
                fn.size = it->second;
                functions.push_back(fn);
                found = true;
            }
            else
            {
                fmt::println("ERROR: Function 0x{:X} NOT found in config.functions map", config.singleFunctionAddress);
            }
        }
    }
    
    for (size_t i = 0; i < functions.size(); i++)
    {
        // If single function mode, skip all others
        if (config.singleFunctionAddress != 0 && functions[i].base != config.singleFunctionAddress)
            continue;

        if ((functionsRecompiled % 256) == 0)
        {
            SaveCurrentOutData();
            println("#include \"x86_recomp_shared.h\"");
            println("");
        }

        if (config.singleFunctionAddress == 0 && ((i % 2048) == 0 || (i == functions.size() - 1)))
        {
            fmt::println("Recompiling functions... {:.1f}%", 
                        static_cast<float>(i + 1) / functions.size() * 100.0f);
        }

        Recompile(functions[i]);
        functionsRecompiled++;

        // If single function mode and we found it, we're done
        if (config.singleFunctionAddress != 0)
        {
            fmt::println("Successfully recompiled function at 0x{:X}", config.singleFunctionAddress);
            break;
        }
    }

    if (config.singleFunctionAddress != 0 && functionsRecompiled == 0)
    {
        fmt::println("ERROR: Function at address 0x{:X} not found anywhere", config.singleFunctionAddress);
    }

    SaveCurrentOutData();
}

void X86Recompiler::SaveCurrentOutData(const std::string_view& name)
{
    if (!out.empty())
    {
        std::string fileName;
        if (name.empty())
        {
            fileName = fmt::format("x86_recomp.{}.cpp", cppFileIndex);
            ++cppFileIndex;
        }

        std::string directoryPath = config.directoryPath;
        if (!directoryPath.empty())
            directoryPath += "/";

        std::string filePath = fmt::format("{}{}/{}", 
            directoryPath, config.outDirectoryPath, name.empty() ? fileName : name);

        // Check if file already exists with same content
        bool shouldWrite = true;
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (fileSize == static_cast<long>(out.size()))
            {
                fseek(f, 0, SEEK_SET);
                std::vector<uint8_t> existing(fileSize);
                fread(existing.data(), 1, fileSize, f);
                shouldWrite = memcmp(existing.data(), out.data(), fileSize) != 0;
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
            }
        }

        out.clear();
    }
}
