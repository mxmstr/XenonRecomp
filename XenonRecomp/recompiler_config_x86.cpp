#include "pch.h"
#include "recompiler_config_x86.h"

void X86RecompilerConfig::Load(const std::string_view& configFilePath)
{
    directoryPath = configFilePath.substr(0, configFilePath.find_last_of("\\/") + 1);
    toml::table toml = toml::parse_file(configFilePath)
#if !TOML_EXCEPTIONS
        .table()
#endif
        ;

    if (auto mainPtr = toml["main"].as_table())
    {
        const auto& main = *mainPtr;
        fmt::println("DEBUG: Found [main] section");
        
        // Check if functions key exists
        auto functionsNode = main["functions"];
        if (functionsNode)
        {
            fmt::println("DEBUG: 'functions' key exists, type: {}", 
                functionsNode.is_array() ? "array" : 
                functionsNode.is_table() ? "table" : 
                functionsNode.is_value() ? "value" : "unknown");
        }
        else
        {
            fmt::println("DEBUG: 'functions' key does NOT exist in [main]");
        }
        
        filePath = main["file_path"].value_or<std::string>("");
        outDirectoryPath = main["out_directory_path"].value_or<std::string>("");
        switchTableFilePath = main["switch_table_file_path"].value_or<std::string>("");

        // Optimization flags
        eaxAsLocal = main["eax_as_local"].value_or(false);
        ecxAsLocal = main["ecx_as_local"].value_or(false);
        edxAsLocal = main["edx_as_local"].value_or(false);
        ebxAsLocal = main["ebx_as_local"].value_or(false);
        esiAsLocal = main["esi_as_local"].value_or(false);
        ediAsLocal = main["edi_as_local"].value_or(false);
        eflagsAsLocal = main["eflags_as_local"].value_or(false);
        fpuAsLocal = main["fpu_as_local"].value_or(false);

        // Special function addresses
        longJmpAddress = main["longjmp_address"].value_or(0u);
        setJmpAddress = main["setjmp_address"].value_or(0u);
        allocaProbeAddress = main["alloca_probe_address"].value_or(0u);
        sehPrologAddress = main["seh_prolog_address"].value_or(0u);
        sehEpilogAddress = main["seh_epilog_address"].value_or(0u);

        // Manual function definitions - check both [main] and top-level
        auto functionsArray = main["functions"].as_array();
        if (!functionsArray)
        {
            functionsArray = toml["functions"].as_array();
        }
        
        if (functionsArray)
        {
            fmt::println("Found functions array in TOML with {} entries", functionsArray->size());
            for (auto& func : *functionsArray)
            {
                auto& funcTable = *func.as_table();
                uint32_t address = *funcTable["address"].value<uint32_t>();
                uint32_t size = *funcTable["size"].value<uint32_t>();
                functions.emplace(address, size);
                
                // Parse function chunks if present
                if (auto chunksArray = funcTable["chunks"].as_array())
                {
                    std::vector<std::pair<uint32_t, uint32_t>> chunks;
                    for (auto& chunk : *chunksArray)
                    {
                        auto& chunkTable = *chunk.as_table();
                        uint32_t chunkAddr = *chunkTable["address"].value<uint32_t>();
                        uint32_t chunkSize = *chunkTable["size"].value<uint32_t>();
                        chunks.emplace_back(chunkAddr, chunkSize);
                    }
                    if (!chunks.empty())
                    {
                        functionChunks.emplace(address, std::move(chunks));
                        fmt::println("  Function 0x{:X} has {} chunks", address, functionChunks[address].size());
                    }
                }
            }
            fmt::println("Loaded {} functions into config.functions map", functions.size());
        }
        else
        {
            fmt::println("WARNING: No functions array found in [main] or top-level");
        }

        // Invalid instruction patterns
        if (auto invalidArray = main["invalid_instructions"].as_array())
        {
            for (auto& instr : *invalidArray)
            {
                auto& instrTable = *instr.as_table();
                uint32_t size = *instrTable["size"].value<uint32_t>();
                
                // Check if it's an address-based entry or data-pattern entry
                if (auto addrVal = instrTable["address"].value<uint32_t>())
                {
                    invalidAddresses.emplace(*addrVal, size);
                }
                else if (auto dataVal = instrTable["data"].value<uint32_t>())
                {
                    invalidInstructions.emplace(*dataVal, size);
                }
            }
        }

        // Load switch tables from separate file
        if (!switchTableFilePath.empty())
        {
            toml::table switchToml = toml::parse_file(directoryPath + switchTableFilePath)
#if !TOML_EXCEPTIONS
                .table()
#endif
                ;
            if (auto switchArray = switchToml["switch"].as_array())
            {
                for (auto& entry : *switchArray)
                {
                    auto& table = *entry.as_table();
                    X86RecompilerSwitchTable switchTable;
                    switchTable.reg = *table["r"].value<uint32_t>();
                    switchTable.defaultLabel = table["default"].value_or(0u);
                    for (auto& label : *table["labels"].as_array())
                    {
                        switchTable.labels.push_back(*label.value<uint32_t>());
                    }
                    switchTables.emplace(*table["base"].value<uint32_t>(), std::move(switchTable));
                }
            }
        }
    }

    // Section configurations (code/data boundaries within mixed sections)
    // Supports both legacy [[section_boundary]] format and new [[section_config]] format
    if (auto sectionBoundaryArray = toml["section_boundary"].as_array())
    {
        for (auto& entry : *sectionBoundaryArray)
        {
            auto& table = *entry.as_table();
            X86RecompilerSectionConfig config;
            config.name = *table["name"].value<std::string>();
            config.codeEndAddress = table["code_end_address"].value_or(0u);
            sectionConfigs.emplace(config.name, std::move(config));
        }
    }

    // New format: [[section_config]] with code_ranges and data_ranges arrays
    if (auto sectionConfigArray = toml["section_config"].as_array())
    {
        for (auto& entry : *sectionConfigArray)
        {
            auto& table = *entry.as_table();
            X86RecompilerSectionConfig config;
            config.name = *table["name"].value<std::string>();

            // Parse code_ranges array of {start, end} tables
            if (auto codeRangesArray = table["code_ranges"].as_array())
            {
                for (auto& rangeEntry : *codeRangesArray)
                {
                    auto& rangeTable = *rangeEntry.as_table();
                    X86RecompilerAddressRange range;
                    range.start = *rangeTable["start"].value<uint32_t>();
                    range.end = *rangeTable["end"].value<uint32_t>();
                    config.codeRanges.push_back(range);
                }
            }

            // Parse data_ranges array of {start, end} tables
            if (auto dataRangesArray = table["data_ranges"].as_array())
            {
                for (auto& rangeEntry : *dataRangesArray)
                {
                    auto& rangeTable = *rangeEntry.as_table();
                    X86RecompilerAddressRange range;
                    range.start = *rangeTable["start"].value<uint32_t>();
                    range.end = *rangeTable["end"].value<uint32_t>();
                    config.dataRanges.push_back(range);
                }
            }

            // Also support legacy code_end_address in section_config
            config.codeEndAddress = table["code_end_address"].value_or(0u);

            sectionConfigs.emplace(config.name, std::move(config));
        }
    }

    // Mid-asm hooks
    if (auto midAsmHookArray = toml["midasm_hook"].as_array())
    {
        for (auto& entry : *midAsmHookArray)
        {
            auto& table = *entry.as_table();

            X86RecompilerMidAsmHook midAsmHook;
            midAsmHook.name = *table["name"].value<std::string>();
            if (auto registerArray = table["registers"].as_array())
            {
                for (auto& reg : *registerArray)
                    midAsmHook.registers.push_back(*reg.value<std::string>());
            }

            midAsmHook.ret = table["return"].value_or(false);
            midAsmHook.returnOnTrue = table["return_on_true"].value_or(false);
            midAsmHook.returnOnFalse = table["return_on_false"].value_or(false);

            midAsmHook.jumpAddress = table["jump_address"].value_or(0u);
            midAsmHook.jumpAddressOnTrue = table["jump_address_on_true"].value_or(0u);
            midAsmHook.jumpAddressOnFalse = table["jump_address_on_false"].value_or(0u);

            if ((midAsmHook.ret && midAsmHook.jumpAddress != 0) ||
                (midAsmHook.returnOnTrue && midAsmHook.jumpAddressOnTrue != 0) ||
                (midAsmHook.returnOnFalse && midAsmHook.jumpAddressOnFalse != 0))
            {
                fmt::println("{}: can't return and jump at the same time", midAsmHook.name);
            }

            if ((midAsmHook.ret || midAsmHook.jumpAddress != 0) &&
                (midAsmHook.returnOnFalse || midAsmHook.returnOnTrue ||
                    midAsmHook.jumpAddressOnFalse != 0 || midAsmHook.jumpAddressOnTrue != 0))
            {
                fmt::println("{}: can't mix direct and conditional return/jump", midAsmHook.name);
            }

            midAsmHook.afterInstruction = table["after_instruction"].value_or(false);

            midAsmHooks.emplace(*table["address"].value<uint32_t>(), std::move(midAsmHook));
        }
    }
}
