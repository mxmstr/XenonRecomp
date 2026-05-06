#include "recompiler_config.h"
#include <toml++/toml.hpp>
#include <fmt/core.h>

void XBERecompConfig::Load(const std::string_view& configFilePath)
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
        filePath = main["file_path"].value_or<std::string>("");
        outDirectoryPath = main["out_directory_path"].value_or<std::string>("");
        switchTableFilePath = main["switch_table_file_path"].value_or<std::string>("");
        ramSize = main["ram_size"].value_or(static_cast<int64_t>(128 * 1024 * 1024));

        if (auto functionsArray = main["functions"].as_array())
        {
            for (auto& func : *functionsArray)
            {
                auto& funcTable = *func.as_table();
                uint32_t address = *funcTable["address"].value<uint32_t>();
                uint32_t size = *funcTable["size"].value<uint32_t>();
                XBERecompFunction funcData;
                funcData.size = size;
                if (auto chunksArray = funcTable["chunks"].as_array())
                {
                    for (auto& chunk : *chunksArray)
                    {
                        auto& chunkTable = *chunk.as_table();
                        XBERecompChunk c;
                        c.address = *chunkTable["address"].value<uint32_t>();
                        c.size = *chunkTable["size"].value<uint32_t>();
                        funcData.chunks.push_back(c);
                    }
                }
                functions.emplace(address, std::move(funcData));
            }
        }

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
                    XBERecompSwitchTable switchTable;
                    switchTable.reg = *table["reg"].value<uint32_t>();
                    for (auto& label : *table["labels"].as_array())
                    {
                        switchTable.labels.push_back(*label.value<uint32_t>());
                    }
                    switchTables.emplace(*table["base"].value<uint32_t>(), std::move(switchTable));
                }
            }
        }
    }

    if (auto midAsmHookArray = toml["midasm_hook"].as_array())
    {
        for (auto& entry : *midAsmHookArray)
        {
            auto& table = *entry.as_table();
            XBERecompMidAsmHook hook;
            hook.name = *table["name"].value<std::string>();
            hook.address = *table["address"].value<uint32_t>();
            hook.ret = table["return"].value_or(false);
            midAsmHooks.emplace(hook.address, std::move(hook));
        }
    }
}
