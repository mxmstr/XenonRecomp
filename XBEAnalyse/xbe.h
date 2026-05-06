#pragma once
#include <cstdint>
#include <memory>

// XBE magic: "XBEH"
constexpr uint32_t XBE_MAGIC = 0x48454258;

// XBE section flags
enum XbeSectionFlags : uint32_t
{
    XBE_SECTION_WRITABLE        = 0x00000001,
    XBE_SECTION_PRELOAD         = 0x00000002,
    XBE_SECTION_EXECUTABLE      = 0x00000004,
    XBE_SECTION_INSERTED_FILE   = 0x00000008,
    XBE_SECTION_HEAD_PAGE_RO    = 0x00000010,
    XBE_SECTION_TAIL_PAGE_RO    = 0x00000020,
};

// XBE init flags
enum XbeInitFlags : uint32_t
{
    XBE_INIT_MOUNT_UTILITY      = 0x00000001,
    XBE_INIT_FORMAT_UTILITY     = 0x00000002,
    XBE_INIT_64MB_RAM           = 0x00000004,
    XBE_INIT_DONT_SETUP_HDD    = 0x00000008,
};

#pragma pack(push, 1)

struct XbeImageHeader
{
    uint32_t magic;                     // 0x000 - "XBEH"
    uint8_t  digitalSignature[256];     // 0x004
    uint32_t baseAddress;               // 0x104
    uint32_t sizeOfHeaders;             // 0x108
    uint32_t sizeOfImage;               // 0x10C
    uint32_t sizeOfImageHeader;         // 0x110
    uint32_t timeDate;                  // 0x114
    uint32_t certificateAddress;        // 0x118
    uint32_t numberOfSections;          // 0x11C
    uint32_t sectionHeadersAddress;     // 0x120
    uint32_t initFlags;                 // 0x124
    uint32_t entryPoint;                // 0x128 - XOR-encoded
    uint32_t tlsAddress;                // 0x12C
    uint32_t peStackCommit;             // 0x130
    uint32_t peHeapReserve;             // 0x134
    uint32_t peHeapCommit;              // 0x138
    uint32_t peBaseAddress;             // 0x13C
    uint32_t peSizeOfImage;             // 0x140
    uint32_t peChecksum;                // 0x144
    uint32_t peTimeDate;                // 0x148
    uint32_t debugPathNameAddress;      // 0x14C
    uint32_t debugFileNameAddress;      // 0x150
    uint32_t debugUnicodeFileNameAddr;  // 0x154
    uint32_t kernelThunkAddress;        // 0x158 - XOR-encoded
    uint32_t nonKernelImportDirAddr;    // 0x15C
    uint32_t numberOfLibraryVersions;   // 0x160
    uint32_t libraryVersionsAddress;    // 0x164
    uint32_t kernelLibraryVersionAddr;  // 0x168
    uint32_t xapiLibraryVersionAddr;    // 0x16C
    uint32_t logoAddress;               // 0x170
    uint32_t logoSize;                  // 0x174
};

struct XbeCertificate
{
    uint32_t size;
    uint32_t timeDate;
    uint32_t titleId;
    uint16_t titleName[40];
    uint32_t altTitleIds[16];
    uint32_t allowedMedia;
    uint32_t gameRegion;
    uint32_t gameRatings;
    uint32_t diskNumber;
    uint32_t version;
    uint8_t  lanKey[16];
    uint8_t  signatureKey[16];
    uint8_t  altSignatureKeys[16][16];
};

struct XbeSectionHeader
{
    uint32_t flags;
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawAddress;
    uint32_t rawSize;
    uint32_t sectionNameAddress;
    uint32_t sectionNameRefCount;
    uint32_t headSharedPageRefCountAddr;
    uint32_t tailSharedPageRefCountAddr;
    uint8_t  sectionDigest[20];
};

struct XbeLibraryVersion
{
    char     name[8];
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint16_t buildVersion;
    uint16_t flags;
};

struct XbeTls
{
    uint32_t dataStartAddress;
    uint32_t dataEndAddress;
    uint32_t tlsIndexAddress;
    uint32_t tlsCallbackAddress;
    uint32_t sizeOfZeroFill;
    uint32_t characteristics;
};

#pragma pack(pop)

// XOR keys for decoding entry point and kernel thunk address
// Retail
constexpr uint32_t XBE_ENTRY_POINT_RETAIL_XOR  = 0xA8FC57AB;
constexpr uint32_t XBE_KERNEL_THUNK_RETAIL_XOR = 0x5B6D40B6;
// Debug
constexpr uint32_t XBE_ENTRY_POINT_DEBUG_XOR   = 0x94859D4B;
constexpr uint32_t XBE_KERNEL_THUNK_DEBUG_XOR  = 0xEFB1F152;

struct Image;
Image XbeLoadImage(const uint8_t* data, size_t dataSize);
