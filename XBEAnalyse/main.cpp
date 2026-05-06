#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>
#include <fstream>
#include <file.h>
#include <image.h>
#include <section.h>
#include <fmt/core.h>
#include <Zydis/Zydis.h>
#include "xbe.h"

struct X86SwitchTable
{
    std::vector<size_t> labels{};
    size_t base{};
    size_t defaultLabel{};
    uint32_t reg{};
};

static std::string out;

template<class... Args>
static void println(fmt::format_string<Args...> fmt, Args&&... args)
{
    fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    out += '\n';
}

// Scan backwards from a jmp reg/jmp [reg*4+table] to find the cmp that determines the switch size
static bool ScanForSwitchBounds(
    const uint8_t* sectionData,
    size_t sectionBase,
    size_t sectionSize,
    size_t jmpOffset,       // offset within section of the indirect jmp
    ZydisRegister indexReg, // the register used as the index
    uint32_t& outCount,
    size_t& outDefault)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

    // We scan backwards by decoding forward from increasing distances
    // Try to find a CMP indexReg, imm within 64 bytes before the jmp
    const size_t searchStart = (jmpOffset > 128) ? (jmpOffset - 128) : 0;

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    size_t offset = searchStart;
    size_t lastCmpOffset = 0;
    uint32_t lastCmpImm = 0;
    size_t lastJaOffset = 0;
    size_t lastJaTarget = 0;
    bool foundCmp = false;

    while (offset < jmpOffset)
    {
        const size_t remaining = sectionSize - offset;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder,
                sectionData + offset,
                remaining,
                &insn, operands)))
        {
            // Look for CMP reg, imm
            if (insn.mnemonic == ZYDIS_MNEMONIC_CMP &&
                insn.operand_count >= 2 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                // Check if comparing the same register (or sub-register)
                ZydisRegister cmpReg = operands[0].reg.value;
                if (cmpReg == indexReg ||
                    ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LEGACY_32, cmpReg) ==
                    ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LEGACY_32, indexReg))
                {
                    lastCmpOffset = offset;
                    lastCmpImm = static_cast<uint32_t>(operands[1].imm.value.u);
                    foundCmp = true;
                }
            }
            // Look for JA / JBE (unsigned conditional branch that guards the switch)
            else if ((insn.mnemonic == ZYDIS_MNEMONIC_JNBE || insn.mnemonic == ZYDIS_MNEMONIC_JNB ||
                      insn.mnemonic == ZYDIS_MNEMONIC_JB || insn.mnemonic == ZYDIS_MNEMONIC_JBE) &&
                     operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && foundCmp)
            {
                lastJaOffset = offset;
                ZyanU64 target = 0;
                ZydisCalcAbsoluteAddress(&insn, &operands[0],
                    sectionBase + offset, &target);
                lastJaTarget = static_cast<size_t>(target);
            }

            offset += insn.length;
        }
        else
        {
            offset++;
        }
    }

    if (!foundCmp)
    {
        return false;
    }

    outCount = lastCmpImm + 1; // cmp sets count as max case value, table has count+1 entries
    outDefault = lastJaTarget;
    return true;
}

// Try to read a jump table of absolute 32-bit addresses
static bool ReadAbsoluteJumpTable(
    const Image& image,
    size_t tableAddress,
    uint32_t count,
    std::vector<size_t>& labels)
{
    const void* tablePtr = image.Find(tableAddress);
    if (!tablePtr)
    {
        return false;
    }

    const size_t imageStart = image.base;
    const size_t imageEnd = image.base + image.size;

    const auto* entries = reinterpret_cast<const uint32_t*>(tablePtr);
    labels.clear();
    labels.reserve(count);
    for (uint32_t i = 0; i < count; i++)
    {
        uint32_t addr = entries[i];
        // Validate that the entry looks like a valid code address within the image
        if (addr < imageStart || addr >= imageEnd)
        {
            break;
        }
        labels.push_back(addr);
    }
    return !labels.empty();
}

static void ScanSectionForSwitchTables(
    const Image& image,
    const Section& section,
    std::vector<X86SwitchTable>& switches)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    size_t offset = 0;
    while (offset < section.size)
    {
        const size_t remaining = section.size - offset;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder,
                section.data + offset,
                remaining,
                &insn, operands)))
        {
            offset++;
            continue;
        }

        // Look for JMP [reg*4 + disp32] — classic absolute jump table pattern
        // This is the pattern MSVC generates: jmp dword ptr [eax*4 + table_addr]
        if (insn.mnemonic == ZYDIS_MNEMONIC_JMP &&
            operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[0].mem.scale == 4 &&
            operands[0].mem.index != ZYDIS_REGISTER_NONE &&
            operands[0].mem.base == ZYDIS_REGISTER_NONE &&
            operands[0].mem.disp.has_displacement)
        {
            const size_t instrAddr = section.base + offset;
            const uint32_t tableAddr = static_cast<uint32_t>(operands[0].mem.disp.value);
            ZydisRegister indexReg = operands[0].mem.index;

            uint32_t count = 0;
            size_t defaultLabel = 0;

            if (ScanForSwitchBounds(section.data, section.base, section.size,
                                    offset, indexReg, count, defaultLabel) && count > 0 && count < 4096)
            {
                X86SwitchTable table{};
                table.base = instrAddr;
                table.reg = indexReg - ZYDIS_REGISTER_EAX; // convert to index
                table.defaultLabel = defaultLabel;

                if (ReadAbsoluteJumpTable(image, tableAddr, count, table.labels))
                {
                    switches.emplace_back(std::move(table));
                }
            }
        }

        offset += insn.length;
    }
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Usage: XBEAnalyse [input XBE file path] [output jump table TOML file path]\n");
        return EXIT_SUCCESS;
    }

    const auto file = LoadFile(argv[1]);
    if (file.empty())
    {
        fprintf(stderr, "Failed to load file: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    if (file.size() < 4 || memcmp(file.data(), "XBEH", 4) != 0)
    {
        fprintf(stderr, "Not a valid XBE file: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    auto image = XbeLoadImage(file.data(), file.size());
    if (image.sections.empty())
    {
        fprintf(stderr, "Failed to parse XBE image\n");
        return EXIT_FAILURE;
    }

    std::vector<X86SwitchTable> switches;

    println("# Generated by XBEAnalyse");
    println("# XBE base address: 0x{:X}", image.base);
    println("# Entry point: 0x{:X}", image.entry_point);
    println("");

    println("# ---- JUMP TABLES ----");
    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }

        ScanSectionForSwitchTables(image, section, switches);
    }

    for (const auto& table : switches)
    {
        println("[[switch]]");
        println("base = 0x{:X}", table.base);
        println("reg = {}", table.reg);
        println("default = 0x{:X}", table.defaultLabel);
        println("labels = [");
        for (const auto& label : table.labels)
        {
            println("    0x{:X},", label);
        }
        println("]");
        println("");
    }

    std::ofstream f(argv[2]);
    f.write(out.data(), out.size());

    fmt::println("Found {} switch tables", switches.size());
    fmt::println("Output written to: {}", argv[2]);

    return EXIT_SUCCESS;
}
