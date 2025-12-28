#include <cassert>
#include <iterator>
#include <set>
#include <algorithm>
#include <file.h>
#include <disasm.h>
#include <disasm_x86.h>
#include <image.h>
#include <xbox.h>
#include <xbe.h>
#include <fmt/core.h>
#include "function.h"
#include "function_x86.h"

// Image architecture types
enum class ImageArch
{
    Unknown,
    PPC,    // Xbox 360 (XEX)
    X86,    // Original Xbox (XBE)
};

#define SWITCH_ABSOLUTE 0
#define SWITCH_COMPUTED 1
#define SWITCH_BYTEOFFSET 2
#define SWITCH_SHORTOFFSET 3

struct SwitchTable
{
    std::vector<size_t> labels{};
    size_t base{};
    size_t defaultLabel{};
    uint32_t r{};
    uint32_t type{};
};

void ReadTable(Image& image, SwitchTable& table)
{
    uint32_t pOffset;
    ppc_insn insn;
    auto* code = (uint32_t*)image.Find(table.base);
    ppc::Disassemble(code, table.base, insn);
    pOffset = insn.operands[1] << 16;

    ppc::Disassemble(code + 1, table.base + 4, insn);
    pOffset += insn.operands[2];

    if (table.type == SWITCH_ABSOLUTE)
    {
        const auto* offsets = (be<uint32_t>*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = offsets[i];
        }
    }
    else if (table.type == SWITCH_COMPUTED)
    {
        uint32_t base;
        uint32_t shift;
        const auto* offsets = (uint8_t*)image.Find(pOffset);

        ppc::Disassemble(code + 4, table.base + 0x10, insn);
        base = insn.operands[1] << 16;

        ppc::Disassemble(code + 5, table.base + 0x14, insn);
        base += insn.operands[2];

        ppc::Disassemble(code + 3, table.base + 0x0C, insn);
        shift = insn.operands[2];

        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = base + (offsets[i] << shift);
        }
    }
    else if (table.type == SWITCH_BYTEOFFSET || table.type == SWITCH_SHORTOFFSET)
    {
        if (table.type == SWITCH_BYTEOFFSET)
        {
            const auto* offsets = (uint8_t*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 3, table.base + 0x0C, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
        else if (table.type == SWITCH_SHORTOFFSET)
        {
            const auto* offsets = (be<uint16_t>*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 5, table.base + 0x14, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
    }
    else
    {
        assert(false);
    }
}

void ScanTable(const uint32_t* code, size_t base, SwitchTable& table)
{
    ppc_insn insn;
    uint32_t cr{ (uint32_t)-1 };
    for (int i = 0; i < 32; i++)
    {
        ppc::Disassemble(&code[-i], base - (4 * i), insn);
        if (insn.opcode == nullptr)
        {
            continue;
        }

        if (cr == -1 && (insn.opcode->id == PPC_INST_BGT || insn.opcode->id == PPC_INST_BGTLR || insn.opcode->id == PPC_INST_BLE || insn.opcode->id == PPC_INST_BLELR))
        {
            cr = insn.operands[0];
            if (insn.opcode->operands[1] != 0)
            {
                table.defaultLabel = insn.operands[1];
            }
        }
        else if (cr != -1)
        {
            if (insn.opcode->id == PPC_INST_CMPLWI && insn.operands[0] == cr)
            {
                table.r = insn.operands[1];
                table.labels.resize(insn.operands[2] + 1);
                table.base = base;
                break;
            }
        }
    }
}

void MakeMask(const uint32_t* instructions, size_t count)
{
    ppc_insn insn;
    for (size_t i = 0; i < count; i++)
    {
        ppc::Disassemble(&instructions[i], 0, insn);
        fmt::println("0x{:X}, // {}", ByteSwap(insn.opcode->opcode | (insn.instruction & insn.opcode->mask)), insn.opcode->name);
    }
}

void* SearchMask(const void* source, const uint32_t* compare, size_t compareCount, size_t size)
{
    assert(size % 4 == 0);
    uint32_t* src = (uint32_t*)source;
    size_t count = size / 4;
    ppc_insn insn;

    for (size_t i = 0; i < count; i++)
    {
        size_t c = 0;
        for (c = 0; c < compareCount; c++)
        {
            ppc::Disassemble(&src[i + c], 0, insn);
            if (insn.opcode == nullptr || insn.opcode->id != compare[c])
            {
                break;
            }
        }

        if (c == compareCount)
        {
            return &src[i];
        }
    }

    return nullptr;
}

static std::string out;

template<class... Args>
static void println(fmt::format_string<Args...> fmt, Args&&... args)
{
    fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    out += '\n';
};

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("XenonAnalyse - Xbox 360/Original Xbox executable analyzer\n\n");
        printf("Usage: XenonAnalyse [input XEX/XBE file path] [output TOML file path]\n\n");
        printf("Supported formats:\n");
        printf("  XEX  - Xbox 360 executable (PowerPC)\n");
        printf("  XBE  - Original Xbox executable (x86)\n\n");
        printf("The tool auto-detects the executable format from the file header.\n");
        return EXIT_SUCCESS;
    }

    const auto file = LoadFile(argv[1]);
    
    // Detect file type and architecture
    ImageArch arch = ImageArch::Unknown;
    
    if (file.size() >= 4)
    {
        if (file[0] == 'X' && file[1] == 'E' && file[2] == 'X' && file[3] == '2')
        {
            arch = ImageArch::PPC;
            fmt::println("Detected: Xbox 360 XEX (PowerPC)");
        }
        else if (file[0] == 'X' && file[1] == 'B' && file[2] == 'E' && file[3] == 'H')
        {
            arch = ImageArch::X86;
            fmt::println("Detected: Original Xbox XBE (x86)");
        }
        else if (file[0] == 0x7F && file[1] == 'E' && file[2] == 'L' && file[3] == 'F')
        {
            arch = ImageArch::PPC; // Assume PPC for ELF (test files)
            fmt::println("Detected: ELF executable (assuming PowerPC)");
        }
    }
    
    if (arch == ImageArch::Unknown)
    {
        fmt::println("ERROR: Unrecognized file format.");
        fmt::println("Expected XEX2 (Xbox 360), XBE (Original Xbox), or ELF executable.");
        return EXIT_FAILURE;
    }
    
    auto image = Image::ParseImage(file.data(), file.size());
    
    if (image.sections.empty())
    {
        fmt::println("ERROR: Failed to parse image or no sections found.");
        return EXIT_FAILURE;
    }

    // Handle XBE (x86) analysis
    if (arch == ImageArch::X86)
    {
        fmt::println("");
        fmt::println("=== XBE Analysis ===");
        fmt::println("Image base: 0x{:08X}", image.base);
        fmt::println("Entry point: 0x{:08X}", image.entry_point);
        fmt::println("Sections: {}", image.sections.size());
        fmt::println("Kernel imports: {}", image.symbols.size());
        fmt::println("");
        
        // Determine output paths
        std::filesystem::path outputPath(argv[2]);
        std::string baseName = outputPath.stem().string();
        std::filesystem::path outputDir = outputPath.parent_path();
        std::string switchTableFileName = baseName + "_switch_tables.toml";
        std::filesystem::path switchTablePath = outputDir / switchTableFileName;
        
        // Find functions in code sections
        fmt::println("Scanning for functions...");
        std::vector<uint32_t> allFunctions;
        
        for (const auto& section : image.sections)
        {
            if (!(section.flags & SectionFlags_Code))
                continue;
                
            auto funcs = FindX86Functions(section.data, section.size, section.base);
            fmt::println("  {} : {} functions found", section.name, funcs.size());
            allFunctions.insert(allFunctions.end(), funcs.begin(), funcs.end());
        }
        
        fmt::println("Total functions found: {}", allFunctions.size());
        
        // Find jump tables
        fmt::println("Scanning for jump tables...");
        std::vector<X86SwitchTable> allTables;
        
        for (const auto& section : image.sections)
        {
            if (!(section.flags & SectionFlags_Code))
                continue;
                
            auto tables = FindX86JumpTables(
                section.data, section.size, section.base,
                file.data(), image.base
            );
            
            fmt::println("  {} : {} jump tables found", section.name, tables.size());
            allTables.insert(allTables.end(), tables.begin(), tables.end());
        }
        
        fmt::println("Total jump tables found: {}", allTables.size());
        
        // Scan for suspicious instructions that indicate data regions
        fmt::println("Scanning for suspicious instructions (likely data)...");
        struct SuspiciousRegion {
            uint32_t address;
            uint32_t size;
            std::string reason;
        };
        std::vector<SuspiciousRegion> suspiciousRegions;
        
        for (const auto& section : image.sections)
        {
            if (!(section.flags & SectionFlags_Code))
                continue;
                
            const uint8_t* data = section.data;
            const uint8_t* dataEnd = data + section.size;
            uint32_t addr = section.base;
            
            while (data < dataEnd)
            {
                x86::Insn insn;
                int len = x86::Disassemble(data, dataEnd - data, addr, insn);
                
                if (len <= 0)
                {
                    data++;
                    addr++;
                    continue;
                }
                
                // Far calls/jumps indicate data misinterpreted as code
                // Xbox uses flat 32-bit mode - no real far calls
                if (insn.type == x86::InsnType::Callf || insn.type == x86::InsnType::Jmpf)
                {
                    suspiciousRegions.push_back({addr, static_cast<uint32_t>(len), "far call/jump"});
                }
                
                data += len;
                addr += len;
            }
        }
        
        if (!suspiciousRegions.empty())
        {
            fmt::println("  Found {} suspicious instructions (likely data regions)", suspiciousRegions.size());
        }
        
        // =============================================
        // Generate main config TOML
        // =============================================
        println("# Generated by XenonAnalyse");
        println("# Original Xbox XBE Recompiler Configuration");
        println("");
        println("[main]");
        
        // Convert backslashes to forward slashes for TOML compatibility
        std::string inputFilePath = argv[1];
        std::replace(inputFilePath.begin(), inputFilePath.end(), '\\', '/');
        
        println("file_path = \"{}\"", inputFilePath);
        println("out_directory_path = \"./x86_out\"");
        if (!allTables.empty())
        {
            println("switch_table_file_path = \"{}\"", switchTableFileName);
        }
        println("");
        
        // Optimization flags (all disabled by default)
        println("# Optimization flags - enable only after recompilation works");
        println("eax_as_local = false");
        println("ecx_as_local = false");
        println("edx_as_local = false");
        println("ebx_as_local = false");
        println("esi_as_local = false");
        println("edi_as_local = false");
        println("eflags_as_local = false");
        println("fpu_as_local = false");
        println("");
        
        // Special function addresses (placeholders)
        println("# Special function addresses - find these in the executable");
        println("# longjmp_address = 0x0");
        println("# setjmp_address = 0x0");
        println("# alloca_probe_address = 0x0");
        println("# seh_prolog_address = 0x0");
        println("# seh_epilog_address = 0x0");
        println("");
        
        // Image info as comments
        println("# ---- IMAGE INFO ----");
        println("# Base address: 0x{:X}", image.base);
        println("# Entry point: 0x{:X}", image.entry_point);
        println("");
        
        // List all sections with their flags as comments
        println("# ---- SECTIONS ----");
        for (const auto& section : image.sections)
        {
            bool isCode = (section.flags & SectionFlags_Code) != 0;
            println("# {} @ 0x{:X} - 0x{:X} (size: 0x{:X}) [{}]", 
                    section.name, section.base, section.base + section.size, section.size,
                    isCode ? "CODE" : "DATA");
        }
        println("");
        
        // Kernel imports as comments
        if (!image.symbols.empty())
        {
            println("# ---- KERNEL IMPORTS ({} total) ----", image.symbols.size());
            for (const auto& symbol : image.symbols)
            {
                println("# 0x{:X}: {}", symbol.address, symbol.name);
            }
            println("");
        }
        
        // Filter out functions that fall within jump table data regions
        // Also track data regions for later use
        std::set<std::pair<uint32_t, uint32_t>> dataRegions;  // (start, end) pairs
        
        for (const auto& table : allTables)
        {
            if (table.tableAddress != 0 && table.caseCount > 0)
            {
                // Jump table is array of dwords
                uint32_t tableStart = table.tableAddress;
                uint32_t tableEnd = tableStart + (table.caseCount * 4);
                
                // Alignment padding often precedes jump tables
                // Tables are typically aligned to 4, 8, or 16 bytes
                // If table is already 16-byte aligned, check for alignment padding before it
                // (e.g., 8B FF CC CC... to pad from previous code to 16-byte boundary)
                // Include up to 15 bytes before table as potential alignment padding
                uint32_t regionStart = tableStart;
                
                // Look at what 16-byte boundary the table is aligned to
                // If it's on a boundary, include up to 15 bytes before as padding
                if ((tableStart & 0xF) == 0)
                {
                    // Already 16-byte aligned - preceding bytes might be padding
                    regionStart = tableStart - 16;  // Conservative: assume up to 16 bytes padding
                }
                else
                {
                    // Not 16-byte aligned - go back to previous 16-byte boundary
                    regionStart = tableStart & ~0xFu;
                }
                
                // Don't extend before valid code range
                if (regionStart >= 0x1000)
                {
                    dataRegions.insert({regionStart, tableEnd});
                }
                else
                {
                    dataRegions.insert({tableStart, tableEnd});
                }
                
                // Also check for index table (byte array used after jump table)
                // These are typically located just after the jump table
                // The index table size matches the max case value
            }
        }
        
        // Remove functions that start within data regions
        size_t originalCount = allFunctions.size();
        allFunctions.erase(
            std::remove_if(allFunctions.begin(), allFunctions.end(),
                [&dataRegions](uint32_t addr) {
                    for (const auto& [start, end] : dataRegions)
                    {
                        if (addr >= start && addr < end)
                            return true;  // Remove this "function"
                    }
                    return false;
                }),
            allFunctions.end()
        );
        
        if (allFunctions.size() < originalCount)
        {
            fmt::println("Filtered out {} false functions in data regions", 
                         originalCount - allFunctions.size());
        }
        
        // Output functions array
        println("# ---- FUNCTIONS ({} total) ----", allFunctions.size());
        println("# Functions with incorrect boundaries should be manually adjusted.");
        println("functions = [");
        
        // Calculate function sizes and output
        for (size_t i = 0; i < allFunctions.size(); i++)
        {
            uint32_t addr = allFunctions[i];
            uint32_t size;
            
            if (i + 1 < allFunctions.size())
            {
                size = allFunctions[i + 1] - addr;
            }
            else
            {
                // Last function - estimate based on section end
                size = 0x100; // default estimate
                for (const auto& section : image.sections)
                {
                    if (addr >= section.base && addr < section.base + section.size)
                    {
                        size = (section.base + section.size) - addr;
                        break;
                    }
                }
            }
            
            println("    {{ address = 0x{:X}, size = 0x{:X} }},", addr, size);
        }
        
        println("]");
        println("");
        
        // Invalid instructions (common patterns + detected suspicious regions)
        println("# ---- INVALID INSTRUCTIONS ----");
        println("# Patterns to skip (padding, exception data, far calls = likely data)");
        println("invalid_instructions = [");
        println("    {{ data = 0xCCCCCCCC, size = 4 }},  # INT3 padding");
        println("    {{ data = 0x00000000, size = 4 }},  # NOP padding");
        
        // Output detected suspicious regions (far calls, etc.)
        if (!suspiciousRegions.empty())
        {
            println("");
            println("    # Auto-detected suspicious instructions (likely data regions):");
            for (const auto& region : suspiciousRegions)
            {
                println("    {{ address = 0x{:X}, size = {} }},  # {}", 
                        region.address, region.size, region.reason);
            }
        }
        println("]");
        println("");
        
        // Mid-asm hooks section (empty template)
        println("# ---- MID-ASM HOOKS ----");
        println("# [[midasm_hook]]");
        println("# name = \"SomeHookFunction\"");
        println("# address = 0x0");
        println("# registers = [\"eax\", \"ecx\"]");
        println("");
        
        // Write main config file
        std::ofstream configFile(argv[2]);
        configFile.write(out.data(), out.size());
        
        fmt::println("");
        fmt::println("Main config written to: {}", argv[2]);
        
        // =============================================
        // Generate switch tables TOML (separate file)
        // =============================================
        out.clear();
        
        println("# Generated by XenonAnalyse");
        println("# Switch tables for Original Xbox XBE");
        println("");
        
        if (!allTables.empty())
        {
            println("# ---- JUMP TABLES ({} total) ----", allTables.size());
            println("");
            
            for (const auto& table : allTables)
            {
                println("[[switch]]");
                println("base = 0x{:X}", table.address);
                println("r = {}", table.indexReg);  // Register number for consistency with PPC format
                if (table.defaultLabel != 0)
                {
                    println("default = 0x{:X}", table.defaultLabel);
                }
                println("labels = [");
                for (const auto& label : table.labels)
                {
                    println("    0x{:X},", label);
                }
                println("]");
                println("");
            }
        }
        else
        {
            println("# No jump tables detected.");
            println("# If you know there are switch statements, you may need to add them manually.");
            println("# Look for patterns like: cmp reg, N; ja default; jmp [table + reg*4]");
            println("");
            println("# Example:");
            println("# [[switch]]");
            println("# base = 0x0       # Address of the indirect jump instruction");
            println("# r = 0            # Index register (0=eax, 1=ecx, 2=edx, 3=ebx, etc.)");
            println("# default = 0x0    # Default case address");
            println("# labels = [");
            println("#     0x0,         # Case 0");
            println("#     0x0,         # Case 1");
            println("# ]");
            println("");
        }
        
        // Write switch tables file
        std::ofstream switchFile(switchTablePath);
        switchFile.write(out.data(), out.size());
        
        fmt::println("Switch tables written to: {}", switchTablePath.string());
        
        return EXIT_SUCCESS;
    }

    // Handle XEX (PPC) analysis - existing code
    auto printTable = [&](const SwitchTable& table)
        {
            println("[[switch]]");
            println("base = 0x{:X}", table.base);
            println("r = {}", table.r);
            println("default = 0x{:X}", table.defaultLabel);
            println("labels = [");
            for (const auto& label : table.labels)
            {
                println("    0x{:X},", label);
            }

            println("]");
            println("");
        };

    std::vector<SwitchTable> switches{};

    println("# Generated by XenonAnalyse");
    println("# Xbox 360 XEX (PowerPC) Analysis");
    println("");

    auto scanPattern = [&](uint32_t* pattern, size_t count, size_t type)
        {
            for (const auto& section : image.sections)
            {
                if (!(section.flags & SectionFlags_Code))
                {
                    continue;
                }

                size_t base = section.base;
                uint8_t* data = section.data;
                uint8_t* dataStart = section.data;
                uint8_t* dataEnd = section.data + section.size;
                while (data < dataEnd && data != nullptr)
                {
                    data = (uint8_t*)SearchMask(data, pattern, count, dataEnd - data);

                    if (data != nullptr)
                    {
                        SwitchTable table{};
                        table.type = type;
                        ScanTable((uint32_t*)data, base + (data - dataStart), table);

                        // fmt::println("{:X} ; jmptable - {}", base + (data - dataStart), table.labels.size());
                        if (table.base != 0)
                        {
                            ReadTable(image, table);
                            printTable(table);
                            switches.emplace_back(std::move(table));
                        }

                        data += 4;
                    }
                    continue;
                }
            }
        };

    uint32_t absoluteSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LWZX,
        PPC_INST_MTCTR,
        PPC_INST_BCTR,
    };

    uint32_t computedSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_RLWINM,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t offsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t wordOffsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LHZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    println("# ---- ABSOLUTE JUMPTABLE ----");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);

    println("# ---- COMPUTED JUMPTABLE ----");
    scanPattern(computedSwitch, std::size(computedSwitch), SWITCH_COMPUTED);

    println("# ---- OFFSETED JUMPTABLE ----");
    scanPattern(offsetSwitch, std::size(offsetSwitch), SWITCH_BYTEOFFSET);
    scanPattern(wordOffsetSwitch, std::size(wordOffsetSwitch), SWITCH_SHORTOFFSET);

    std::ofstream f(argv[2]);
    f.write(out.data(), out.size());

    return EXIT_SUCCESS;
}
