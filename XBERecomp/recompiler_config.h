#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

struct XBERecompSwitchTable
{
    uint32_t reg;
    std::vector<uint32_t> labels;
};

struct XBERecompChunk
{
    uint32_t address;
    uint32_t size;
};

struct XBERecompFunction
{
    uint32_t size;
    std::vector<XBERecompChunk> chunks;
};

struct XBERecompMidAsmHook
{
    std::string name;
    uint32_t address = 0;
    bool ret = false;
};

struct XBERecompConfig
{
    std::string directoryPath;
    std::string filePath;
    std::string outDirectoryPath;
    std::string switchTableFilePath;
    uint64_t ramSize = 128 * 1024 * 1024; // 128MB default (64MB Xbox RAM + overhead)
    std::unordered_map<uint32_t, XBERecompSwitchTable> switchTables;
    std::unordered_map<uint32_t, XBERecompFunction> functions;
    std::unordered_map<uint32_t, XBERecompMidAsmHook> midAsmHooks;

    void Load(const std::string_view& configFilePath);
};
