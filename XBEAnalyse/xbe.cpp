#include "xbe.h"
#include <image.h>
#include <section.h>
#include <cstring>

Image XbeLoadImage(const uint8_t* data, size_t dataSize)
{
    if (dataSize < sizeof(XbeImageHeader))
    {
        return {};
    }

    const auto* header = reinterpret_cast<const XbeImageHeader*>(data);
    if (header->magic != XBE_MAGIC)
    {
        return {};
    }

    const uint32_t baseAddress = header->baseAddress;

    // Decode entry point (try retail XOR first, then debug)
    uint32_t entryPoint = header->entryPoint ^ XBE_ENTRY_POINT_RETAIL_XOR;
    if (entryPoint < baseAddress || entryPoint >= baseAddress + header->sizeOfImage)
    {
        entryPoint = header->entryPoint ^ XBE_ENTRY_POINT_DEBUG_XOR;
    }

    // Decode kernel thunk address
    uint32_t kernelThunk = header->kernelThunkAddress ^ XBE_KERNEL_THUNK_RETAIL_XOR;
    if (kernelThunk < baseAddress || kernelThunk >= baseAddress + header->sizeOfImage)
    {
        kernelThunk = header->kernelThunkAddress ^ XBE_KERNEL_THUNK_DEBUG_XOR;
    }

    Image image{};
    image.base = baseAddress;
    image.entry_point = entryPoint;
    image.size = header->sizeOfImage;
    image.data = std::make_unique<uint8_t[]>(header->sizeOfImage);
    memset(image.data.get(), 0, header->sizeOfImage);

    // Copy headers into image
    const uint32_t headerCopy = (header->sizeOfHeaders < header->sizeOfImage) ? header->sizeOfHeaders : header->sizeOfImage;
    memcpy(image.data.get(), data, headerCopy);

    // Map sections
    const auto* sections = reinterpret_cast<const XbeSectionHeader*>(
        data + (header->sectionHeadersAddress - baseAddress));

    for (uint32_t i = 0; i < header->numberOfSections; i++)
    {
        const auto& section = sections[i];

        // Copy raw data into image at virtual offset
        const uint32_t virtualOffset = section.virtualAddress - baseAddress;
        const uint32_t copySize = (section.rawSize < section.virtualSize) ? section.rawSize : section.virtualSize;

        if (section.rawAddress + copySize <= dataSize && virtualOffset + section.virtualSize <= header->sizeOfImage)
        {
            memcpy(image.data.get() + virtualOffset, data + section.rawAddress, copySize);
        }

        // Get section name
        const char* sectionName = "unknown";
        if (section.sectionNameAddress >= baseAddress)
        {
            const uint32_t nameOffset = section.sectionNameAddress - baseAddress;
            if (nameOffset < dataSize)
            {
                sectionName = reinterpret_cast<const char*>(data + nameOffset);
            }
        }

        uint8_t flags = SectionFlags_Data;
        if (section.flags & XBE_SECTION_EXECUTABLE)
        {
            flags = SectionFlags_Code;
        }

        image.Map(sectionName, virtualOffset, section.virtualSize, flags, image.data.get() + virtualOffset);
    }

    return image;
}
