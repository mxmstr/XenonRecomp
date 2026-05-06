#include "recompiler.h"
#include <cstdio>
#include <filesystem>

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: XBERecomp [config.toml]\n");
        return EXIT_SUCCESS;
    }

    const char* configPath = argv[1];

    if (!std::filesystem::is_regular_file(configPath))
    {
        printf("ERROR: Config file not found: %s\n", configPath);
        return EXIT_FAILURE;
    }

    XBERecompiler recompiler;

    if (!recompiler.LoadConfig(configPath))
        return EXIT_FAILURE;

    if (!recompiler.LoadXBE())
        return EXIT_FAILURE;

    recompiler.Analyse();

    if (!recompiler.HookKernelImports())
        return EXIT_FAILURE;

    if (!recompiler.Recompile())
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
