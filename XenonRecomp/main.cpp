#include "pch.h"
#include "test_recompiler.h"
#include "recompiler_x86.h"
#include <xbe.h>

enum class ExecutableType
{
    Unknown,
    XEX,    // Xbox 360
    XBE     // Original Xbox
};

static ExecutableType DetectExecutableType(const std::string_view& configPath)
{
    // Parse config to get the file path
    try
    {
        auto config = toml::parse_file(configPath);
        auto filePath = config["main"]["file_path"].value<std::string>();
        if (filePath)
        {
            std::string path = *filePath;
            std::filesystem::path p(path);
            std::string ext = p.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            
            if (ext == ".xbe")
                return ExecutableType::XBE;
            else if (ext == ".xex")
                return ExecutableType::XEX;
            
            // Try to detect by magic number
            std::string configDir = std::filesystem::path(configPath).parent_path().string();
            if (!configDir.empty())
                configDir += "/";
            
            std::ifstream f(configDir + path, std::ios::binary);
            if (f.good())
            {
                char magic[4];
                f.read(magic, 4);
                if (memcmp(magic, "XBEH", 4) == 0)
                    return ExecutableType::XBE;
                else if (memcmp(magic, "XEX2", 4) == 0 || memcmp(magic, "XEX1", 4) == 0)
                    return ExecutableType::XEX;
            }
        }
    }
    catch (...)
    {
        // Parsing failed, default to XEX
    }
    
    return ExecutableType::Unknown;
}

int main(int argc, char* argv[])
{
#ifndef XENON_RECOMP_CONFIG_FILE_PATH
    if (argc < 3)
    {
        printf("XenonRecomp - Xbox 360/Original Xbox static recompiler\n\n");
        printf("Usage: XenonRecomp [input TOML file path] [context header file path] [options]\n\n");
        printf("Arguments:\n");
        printf("  TOML file      - Configuration file for the recompiler\n");
        printf("  context header - For XEX files: ppc_context.h\n");
        printf("                   For XBE files: x86_context.h\n\n");
        printf("Options:\n");
        printf("  --function <address>  - Recompile only a single function at the given address\n");
        printf("                          Address should be in hex format (e.g., 0x24C05C)\n\n");
        printf("The executable type (XEX/XBE) is auto-detected from the TOML config.\n");
        return EXIT_SUCCESS;
    }
#endif

    const char* path = 
    #ifdef XENON_RECOMP_CONFIG_FILE_PATH
        XENON_RECOMP_CONFIG_FILE_PATH
    #else
        argv[1]
    #endif
        ;

    // Parse optional --function argument
    uint32_t singleFunctionAddress = 0;
    for (int i = 3; i < argc; i++)
    {
        if (strcmp(argv[i], "--function") == 0 && i + 1 < argc)
        {
            // Parse hex address
            char* endPtr;
            singleFunctionAddress = strtoul(argv[i + 1], &endPtr, 0);
            if (*endPtr != '\0')
            {
                fmt::println("Error: Invalid function address '{}'", argv[i + 1]);
                return EXIT_FAILURE;
            }
            fmt::println("Recompiling single function at address: 0x{:X}", singleFunctionAddress);
            i++; // Skip address argument
        }
    }

    if (std::filesystem::is_regular_file(path))
    {
        ExecutableType exeType = DetectExecutableType(path);
        
        const char* headerFilePath =
#ifdef XENON_RECOMP_HEADER_FILE_PATH
            XENON_RECOMP_HEADER_FILE_PATH
#else
            argv[2]
#endif
            ;

        if (exeType == ExecutableType::XBE)
        {
            fmt::println("Detected XBE (Original Xbox) executable");
            
            X86Recompiler recompiler;
            if (!recompiler.LoadConfig(path))
                return -1;

            recompiler.config.singleFunctionAddress = singleFunctionAddress;
            recompiler.Analyse();

            auto entry = recompiler.image.symbols.find(recompiler.image.entry_point);
            if (entry != recompiler.image.symbols.end())
            {
                Symbol updated = *entry;
                updated.name = "_xstart";
                recompiler.image.symbols.erase(entry);
                recompiler.image.symbols.insert(updated);
            }

            recompiler.Recompile(headerFilePath);
        }
        else
        {
            if (exeType == ExecutableType::Unknown)
                fmt::println("Unknown executable type, defaulting to XEX (Xbox 360)");
            else
                fmt::println("Detected XEX (Xbox 360) executable");
            
            Recompiler recompiler;
            if (!recompiler.LoadConfig(path))
                return -1;

            recompiler.config.singleFunctionAddress = singleFunctionAddress;
            recompiler.Analyse();

            auto entry = recompiler.image.symbols.find(recompiler.image.entry_point);
            if (entry != recompiler.image.symbols.end())
            {
                entry->name = "_xstart";
            }

            recompiler.Recompile(headerFilePath);
        }
    }
    else
    {
        TestRecompiler::RecompileTests(path, argv[2]);
    }

    return EXIT_SUCCESS;
}
