#pragma once
#include <cstdint>
#include <memory>
#include "image.h"

// XBE Magic: "XBEH" (little-endian)
inline constexpr uint32_t XBE_MAGIC = 0x48454258;

// XBE Section Flags
enum XbeSectionFlags : uint32_t
{
    XBE_SECTION_WRITABLE = 0x00000001,
    XBE_SECTION_PRELOAD = 0x00000002,
    XBE_SECTION_EXECUTABLE = 0x00000004,
    XBE_SECTION_INSERTED_FILE = 0x00000008,
    XBE_SECTION_HEAD_PAGE_READ_ONLY = 0x00000010,
    XBE_SECTION_TAIL_PAGE_READ_ONLY = 0x00000020,
};

// XBE Library Flags
enum XbeLibraryFlags : uint16_t
{
    XBE_LIBRARY_DEBUG = 0x0001,
    XBE_LIBRARY_APPROVED = 0x0002,
};

#pragma pack(push, 1)

struct XbeHeader
{
    uint32_t magic;                     // 0x0000 - "XBEH"
    uint8_t  signature[256];            // 0x0004 - Digital signature
    uint32_t baseAddress;               // 0x0104 - Base address (usually 0x00010000)
    uint32_t headersSize;               // 0x0108 - Size of all headers
    uint32_t imageSize;                 // 0x010C - Size of entire image
    uint32_t imageHeaderSize;           // 0x0110 - Size of this header
    uint32_t timestamp;                 // 0x0114 - Timestamp
    uint32_t certificateAddress;        // 0x0118 - Certificate address
    uint32_t sectionCount;              // 0x011C - Number of sections
    uint32_t sectionHeadersAddress;     // 0x0120 - Section headers address
    uint32_t initFlags;                 // 0x0124 - Initialization flags
    uint32_t entryPoint;                // 0x0128 - Entry point (XOR encrypted)
    uint32_t tlsAddress;                // 0x012C - TLS directory address
    uint32_t peStackCommit;             // 0x0130 - PE stack commit
    uint32_t peHeapReserve;             // 0x0134 - PE heap reserve
    uint32_t peHeapCommit;              // 0x0138 - PE heap commit
    uint32_t peBaseAddress;             // 0x013C - PE base address
    uint32_t peSizeOfImage;             // 0x0140 - PE size of image
    uint32_t peChecksum;                // 0x0144 - PE checksum
    uint32_t peTimestamp;               // 0x0148 - PE timestamp
    uint32_t debugPathNameAddress;      // 0x014C - Debug path name address
    uint32_t debugFileNameAddress;      // 0x0150 - Debug file name address
    uint32_t debugUnicodeFileNameAddress; // 0x0154 - Debug unicode file name address
    uint32_t kernelThunkAddress;        // 0x0158 - Kernel thunk table address (XOR encrypted)
    uint32_t nonKernelImportDirAddress; // 0x015C - Non-kernel import directory address
    uint32_t libraryVersionCount;       // 0x0160 - Number of library versions
    uint32_t libraryVersionsAddress;    // 0x0164 - Library versions address
    uint32_t kernelLibraryVersionAddress; // 0x0168 - Kernel library version address
    uint32_t xapiLibraryVersionAddress; // 0x016C - XAPI library version address
    uint32_t logoAddress;               // 0x0170 - Logo bitmap address
    uint32_t logoSize;                  // 0x0174 - Logo bitmap size
};

struct XbeSectionHeader
{
    uint32_t flags;                     // Section flags
    uint32_t virtualAddress;            // Virtual address
    uint32_t virtualSize;               // Virtual size
    uint32_t rawAddress;                // Raw address (file offset)
    uint32_t rawSize;                   // Raw size
    uint32_t sectionNameAddress;        // Section name address
    uint32_t sectionNameRefCount;       // Section name reference count
    uint32_t headSharedPageRefCountAddress; // Head shared page ref count address
    uint32_t tailSharedPageRefCountAddress; // Tail shared page ref count address
    uint8_t  sectionDigest[20];         // Section digest (SHA1)
};

struct XbeCertificate
{
    uint32_t size;                      // Certificate size
    uint32_t timestamp;                 // Certificate timestamp
    uint32_t titleId;                   // Title ID
    uint16_t titleName[40];             // Title name (Unicode)
    uint32_t alternativeTitleIds[16];   // Alternative title IDs
    uint32_t allowedMedia;              // Allowed media types
    uint32_t gameRegion;                // Game region
    uint32_t gameRatings;               // Game ratings
    uint32_t diskNumber;                // Disk number
    uint32_t version;                   // Version
    uint8_t  lanKey[16];                // LAN key
    uint8_t  signatureKey[16];          // Signature key
    uint8_t  alternativeSignatureKeys[16][16]; // Alternative signature keys
};

struct XbeLibraryVersion
{
    char     name[8];                   // Library name
    uint16_t majorVersion;              // Major version
    uint16_t minorVersion;              // Minor version
    uint16_t buildVersion;              // Build version
    uint16_t flags;                     // Library flags
};

struct XbeTls
{
    uint32_t dataStartAddress;          // TLS data start address
    uint32_t dataEndAddress;            // TLS data end address
    uint32_t indexAddress;              // TLS index address
    uint32_t callbacksAddress;          // TLS callbacks address
    uint32_t sizeOfZeroFill;            // Size of zero fill
    uint32_t characteristics;           // Characteristics
};

#pragma pack(pop)

// Entry point XOR keys for decryption
// Retail key
inline constexpr uint32_t XBE_ENTRY_POINT_RETAIL_KEY = 0xA8FC57AB;
// Debug key  
inline constexpr uint32_t XBE_ENTRY_POINT_DEBUG_KEY = 0x94859D4B;

// Kernel thunk XOR keys
inline constexpr uint32_t XBE_KERNEL_THUNK_RETAIL_KEY = 0x5B6D40B6;
inline constexpr uint32_t XBE_KERNEL_THUNK_DEBUG_KEY = 0xEFB1F152;

// Load XBE image
Image XbeLoadImage(const uint8_t* data, size_t size);

// Get title name from XBE certificate (as ASCII)
std::string XbeGetTitleName(const XbeCertificate* cert);
