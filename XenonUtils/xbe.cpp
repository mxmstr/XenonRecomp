#include "xbe.h"
#include <cassert>
#include <cstring>
#include <fmt/core.h>

// Original Xbox kernel function table (from Xemu/Cxbx-Reloaded)
// Maps ordinal to function name
#define STRINGIFY(X) #X
#define XBE_EXPORT(ORDINAL, NAME) { (ORDINAL), "__imp__" STRINGIFY(NAME) }

static const std::pair<uint32_t, const char*> g_xboxkrnlExports[] = {
    XBE_EXPORT(1, AvGetSavedDataAddress),
    XBE_EXPORT(2, AvSendTVEncoderOption),
    XBE_EXPORT(3, AvSetDisplayMode),
    XBE_EXPORT(4, AvSetSavedDataAddress),
    XBE_EXPORT(5, DbgBreakPoint),
    XBE_EXPORT(6, DbgBreakPointWithStatus),
    XBE_EXPORT(7, DbgLoadImageSymbols),
    XBE_EXPORT(8, DbgPrint),
    XBE_EXPORT(9, HalReadSMCTrayState),
    XBE_EXPORT(10, DbgPrompt),
    XBE_EXPORT(11, DbgUnLoadImageSymbols),
    XBE_EXPORT(12, ExAcquireReadWriteLockExclusive),
    XBE_EXPORT(13, ExAcquireReadWriteLockShared),
    XBE_EXPORT(14, ExAllocatePool),
    XBE_EXPORT(15, ExAllocatePoolWithTag),
    XBE_EXPORT(16, ExEventObjectType),
    XBE_EXPORT(17, ExFreePool),
    XBE_EXPORT(18, ExInitializeReadWriteLock),
    XBE_EXPORT(19, ExInterlockedAddLargeInteger),
    XBE_EXPORT(20, ExInterlockedAddLargeStatistic),
    XBE_EXPORT(21, ExInterlockedCompareExchange64),
    XBE_EXPORT(22, ExMutantObjectType),
    XBE_EXPORT(23, ExQueryPoolBlockSize),
    XBE_EXPORT(24, ExQueryNonVolatileSetting),
    XBE_EXPORT(25, ExReadWriteRefurbInfo),
    XBE_EXPORT(26, ExRaiseException),
    XBE_EXPORT(27, ExRaiseStatus),
    XBE_EXPORT(28, ExReleaseReadWriteLock),
    XBE_EXPORT(29, ExSaveNonVolatileSetting),
    XBE_EXPORT(30, ExSemaphoreObjectType),
    XBE_EXPORT(31, ExTimerObjectType),
    XBE_EXPORT(32, ExfInterlockedInsertHeadList),
    XBE_EXPORT(33, ExfInterlockedInsertTailList),
    XBE_EXPORT(34, ExfInterlockedRemoveHeadList),
    XBE_EXPORT(35, FscGetCacheSize),
    XBE_EXPORT(36, FscInvalidateIdleBlocks),
    XBE_EXPORT(37, FscSetCacheSize),
    XBE_EXPORT(38, HalClearSoftwareInterrupt),
    XBE_EXPORT(39, HalDisableSystemInterrupt),
    XBE_EXPORT(40, HalDiskCachePartitionCount),
    XBE_EXPORT(41, HalDiskModelNumber),
    XBE_EXPORT(42, HalDiskSerialNumber),
    XBE_EXPORT(43, HalEnableSystemInterrupt),
    XBE_EXPORT(44, HalGetInterruptVector),
    XBE_EXPORT(45, HalReadSMBusValue),
    XBE_EXPORT(46, HalReadWritePCISpace),
    XBE_EXPORT(47, HalRegisterShutdownNotification),
    XBE_EXPORT(48, HalRequestSoftwareInterrupt),
    XBE_EXPORT(49, HalReturnToFirmware),
    XBE_EXPORT(50, HalWriteSMBusValue),
    XBE_EXPORT(51, InterlockedCompareExchange),
    XBE_EXPORT(52, InterlockedDecrement),
    XBE_EXPORT(53, InterlockedIncrement),
    XBE_EXPORT(54, InterlockedExchange),
    XBE_EXPORT(55, InterlockedExchangeAdd),
    XBE_EXPORT(56, InterlockedFlushSList),
    XBE_EXPORT(57, InterlockedPopEntrySList),
    XBE_EXPORT(58, InterlockedPushEntrySList),
    XBE_EXPORT(59, IoAllocateIrp),
    XBE_EXPORT(60, IoBuildAsynchronousFsdRequest),
    XBE_EXPORT(61, IoBuildDeviceIoControlRequest),
    XBE_EXPORT(62, IoBuildSynchronousFsdRequest),
    XBE_EXPORT(63, IoCheckShareAccess),
    XBE_EXPORT(64, IoCompletionObjectType),
    XBE_EXPORT(65, IoCreateDevice),
    XBE_EXPORT(66, IoCreateFile),
    XBE_EXPORT(67, IoCreateSymbolicLink),
    XBE_EXPORT(68, IoDeleteDevice),
    XBE_EXPORT(69, IoDeleteSymbolicLink),
    XBE_EXPORT(70, IoDeviceObjectType),
    XBE_EXPORT(71, IoFileObjectType),
    XBE_EXPORT(72, IoFreeIrp),
    XBE_EXPORT(73, IoInitializeIrp),
    XBE_EXPORT(74, IoInvalidDeviceRequest),
    XBE_EXPORT(75, IoQueryFileInformation),
    XBE_EXPORT(76, IoQueryVolumeInformation),
    XBE_EXPORT(77, IoQueueThreadIrp),
    XBE_EXPORT(78, IoRemoveShareAccess),
    XBE_EXPORT(79, IoSetIoCompletion),
    XBE_EXPORT(80, IoSetShareAccess),
    XBE_EXPORT(81, IoStartNextPacket),
    XBE_EXPORT(82, IoStartNextPacketByKey),
    XBE_EXPORT(83, IoStartPacket),
    XBE_EXPORT(84, IoSynchronousDeviceIoControlRequest),
    XBE_EXPORT(85, IoSynchronousFsdRequest),
    XBE_EXPORT(86, IofCallDriver),
    XBE_EXPORT(87, IofCompleteRequest),
    XBE_EXPORT(88, KdDebuggerEnabled),
    XBE_EXPORT(89, KdDebuggerNotPresent),
    XBE_EXPORT(90, IoDismountVolume),
    XBE_EXPORT(91, IoDismountVolumeByName),
    XBE_EXPORT(92, KeAlertResumeThread),
    XBE_EXPORT(93, KeAlertThread),
    XBE_EXPORT(94, KeBoostPriorityThread),
    XBE_EXPORT(95, KeBugCheck),
    XBE_EXPORT(96, KeBugCheckEx),
    XBE_EXPORT(97, KeCancelTimer),
    XBE_EXPORT(98, KeConnectInterrupt),
    XBE_EXPORT(99, KeDelayExecutionThread),
    XBE_EXPORT(100, KeDisconnectInterrupt),
    XBE_EXPORT(101, KeEnterCriticalRegion),
    XBE_EXPORT(102, MmGlobalData),
    XBE_EXPORT(103, KeGetCurrentIrql),
    XBE_EXPORT(104, KeGetCurrentThread),
    XBE_EXPORT(105, KeInitializeApc),
    XBE_EXPORT(106, KeInitializeDeviceQueue),
    XBE_EXPORT(107, KeInitializeDpc),
    XBE_EXPORT(108, KeInitializeEvent),
    XBE_EXPORT(109, KeInitializeInterrupt),
    XBE_EXPORT(110, KeInitializeMutant),
    XBE_EXPORT(111, KeInitializeQueue),
    XBE_EXPORT(112, KeInitializeSemaphore),
    XBE_EXPORT(113, KeInitializeTimerEx),
    XBE_EXPORT(114, KeInsertByKeyDeviceQueue),
    XBE_EXPORT(115, KeInsertDeviceQueue),
    XBE_EXPORT(116, KeInsertHeadQueue),
    XBE_EXPORT(117, KeInsertQueue),
    XBE_EXPORT(118, KeInsertQueueApc),
    XBE_EXPORT(119, KeInsertQueueDpc),
    XBE_EXPORT(120, KeInterruptTime),
    XBE_EXPORT(121, KeIsExecutingDpc),
    XBE_EXPORT(122, KeLeaveCriticalRegion),
    XBE_EXPORT(123, KePulseEvent),
    XBE_EXPORT(124, KeQueryBasePriorityThread),
    XBE_EXPORT(125, KeQueryInterruptTime),
    XBE_EXPORT(126, KeQueryPerformanceCounter),
    XBE_EXPORT(127, KeQueryPerformanceFrequency),
    XBE_EXPORT(128, KeQuerySystemTime),
    XBE_EXPORT(129, KeRaiseIrqlToDpcLevel),
    XBE_EXPORT(130, KeRaiseIrqlToSynchLevel),
    XBE_EXPORT(131, KeReleaseMutant),
    XBE_EXPORT(132, KeReleaseSemaphore),
    XBE_EXPORT(133, KeRemoveByKeyDeviceQueue),
    XBE_EXPORT(134, KeRemoveDeviceQueue),
    XBE_EXPORT(135, KeRemoveEntryDeviceQueue),
    XBE_EXPORT(136, KeRemoveQueue),
    XBE_EXPORT(137, KeRemoveQueueDpc),
    XBE_EXPORT(138, KeResetEvent),
    XBE_EXPORT(139, KeRestoreFloatingPointState),
    XBE_EXPORT(140, KeResumeThread),
    XBE_EXPORT(141, KeRundownQueue),
    XBE_EXPORT(142, KeSaveFloatingPointState),
    XBE_EXPORT(143, KeSetBasePriorityThread),
    XBE_EXPORT(144, KeSetDisableBoostThread),
    XBE_EXPORT(145, KeSetEvent),
    XBE_EXPORT(146, KeSetEventBoostPriority),
    XBE_EXPORT(147, KeSetPriorityProcess),
    XBE_EXPORT(148, KeSetPriorityThread),
    XBE_EXPORT(149, KeSetTimer),
    XBE_EXPORT(150, KeSetTimerEx),
    XBE_EXPORT(151, KeStallExecutionProcessor),
    XBE_EXPORT(152, KeSuspendThread),
    XBE_EXPORT(153, KeSynchronizeExecution),
    XBE_EXPORT(154, KeSystemTime),
    XBE_EXPORT(155, KeTestAlertThread),
    XBE_EXPORT(156, KeTickCount),
    XBE_EXPORT(157, KeTimeIncrement),
    XBE_EXPORT(158, KeWaitForMultipleObjects),
    XBE_EXPORT(159, KeWaitForSingleObject),
    XBE_EXPORT(160, KfRaiseIrql),
    XBE_EXPORT(161, KfLowerIrql),
    XBE_EXPORT(162, KiBugCheckData),
    XBE_EXPORT(163, KiUnlockDispatcherDatabase),
    XBE_EXPORT(164, LaunchDataPage),
    XBE_EXPORT(165, MmAllocateContiguousMemory),
    XBE_EXPORT(166, MmAllocateContiguousMemoryEx),
    XBE_EXPORT(167, MmAllocateSystemMemory),
    XBE_EXPORT(168, MmClaimGpuInstanceMemory),
    XBE_EXPORT(169, MmCreateKernelStack),
    XBE_EXPORT(170, MmDeleteKernelStack),
    XBE_EXPORT(171, MmFreeContiguousMemory),
    XBE_EXPORT(172, MmFreeSystemMemory),
    XBE_EXPORT(173, MmGetPhysicalAddress),
    XBE_EXPORT(174, MmIsAddressValid),
    XBE_EXPORT(175, MmLockUnlockBufferPages),
    XBE_EXPORT(176, MmLockUnlockPhysicalPage),
    XBE_EXPORT(177, MmMapIoSpace),
    XBE_EXPORT(178, MmPersistContiguousMemory),
    XBE_EXPORT(179, MmQueryAddressProtect),
    XBE_EXPORT(180, MmQueryAllocationSize),
    XBE_EXPORT(181, MmQueryStatistics),
    XBE_EXPORT(182, MmSetAddressProtect),
    XBE_EXPORT(183, MmUnmapIoSpace),
    XBE_EXPORT(184, NtAllocateVirtualMemory),
    XBE_EXPORT(185, NtCancelTimer),
    XBE_EXPORT(186, NtClearEvent),
    XBE_EXPORT(187, NtClose),
    XBE_EXPORT(188, NtCreateDirectoryObject),
    XBE_EXPORT(189, NtCreateEvent),
    XBE_EXPORT(190, NtCreateFile),
    XBE_EXPORT(191, NtCreateIoCompletion),
    XBE_EXPORT(192, NtCreateMutant),
    XBE_EXPORT(193, NtCreateSemaphore),
    XBE_EXPORT(194, NtCreateTimer),
    XBE_EXPORT(195, NtDeleteFile),
    XBE_EXPORT(196, NtDeviceIoControlFile),
    XBE_EXPORT(197, NtDuplicateObject),
    XBE_EXPORT(198, NtFlushBuffersFile),
    XBE_EXPORT(199, NtFreeVirtualMemory),
    XBE_EXPORT(200, NtFsControlFile),
    XBE_EXPORT(201, NtOpenDirectoryObject),
    XBE_EXPORT(202, NtOpenFile),
    XBE_EXPORT(203, NtOpenSymbolicLinkObject),
    XBE_EXPORT(204, NtProtectVirtualMemory),
    XBE_EXPORT(205, NtPulseEvent),
    XBE_EXPORT(206, NtQueueApcThread),
    XBE_EXPORT(207, NtQueryDirectoryFile),
    XBE_EXPORT(208, NtQueryDirectoryObject),
    XBE_EXPORT(209, NtQueryEvent),
    XBE_EXPORT(210, NtQueryFullAttributesFile),
    XBE_EXPORT(211, NtQueryInformationFile),
    XBE_EXPORT(212, NtQueryIoCompletion),
    XBE_EXPORT(213, NtQueryMutant),
    XBE_EXPORT(214, NtQuerySemaphore),
    XBE_EXPORT(215, NtQuerySymbolicLinkObject),
    XBE_EXPORT(216, NtQueryTimer),
    XBE_EXPORT(217, NtQueryVirtualMemory),
    XBE_EXPORT(218, NtQueryVolumeInformationFile),
    XBE_EXPORT(219, NtReadFile),
    XBE_EXPORT(220, NtReadFileScatter),
    XBE_EXPORT(221, NtReleaseMutant),
    XBE_EXPORT(222, NtReleaseSemaphore),
    XBE_EXPORT(223, NtRemoveIoCompletion),
    XBE_EXPORT(224, NtResumeThread),
    XBE_EXPORT(225, NtSetEvent),
    XBE_EXPORT(226, NtSetInformationFile),
    XBE_EXPORT(227, NtSetIoCompletion),
    XBE_EXPORT(228, NtSetSystemTime),
    XBE_EXPORT(229, NtSetTimerEx),
    XBE_EXPORT(230, NtSignalAndWaitForSingleObjectEx),
    XBE_EXPORT(231, NtSuspendThread),
    XBE_EXPORT(232, NtUserIoApcDispatcher),
    XBE_EXPORT(233, NtWaitForSingleObject),
    XBE_EXPORT(234, NtWaitForSingleObjectEx),
    XBE_EXPORT(235, NtWaitForMultipleObjectsEx),
    XBE_EXPORT(236, NtWriteFile),
    XBE_EXPORT(237, NtWriteFileGather),
    XBE_EXPORT(238, NtYieldExecution),
    XBE_EXPORT(239, ObCreateObject),
    XBE_EXPORT(240, ObDirectoryObjectType),
    XBE_EXPORT(241, ObInsertObject),
    XBE_EXPORT(242, ObMakeTemporaryObject),
    XBE_EXPORT(243, ObOpenObjectByName),
    XBE_EXPORT(244, ObOpenObjectByPointer),
    XBE_EXPORT(245, ObpObjectHandleTable),
    XBE_EXPORT(246, ObReferenceObjectByHandle),
    XBE_EXPORT(247, ObReferenceObjectByName),
    XBE_EXPORT(248, ObReferenceObjectByPointer),
    XBE_EXPORT(249, ObSymbolicLinkObjectType),
    XBE_EXPORT(250, ObfDereferenceObject),
    XBE_EXPORT(251, ObfReferenceObject),
    XBE_EXPORT(252, PhyGetLinkState),
    XBE_EXPORT(253, PhyInitialize),
    XBE_EXPORT(254, PsCreateSystemThread),
    XBE_EXPORT(255, PsCreateSystemThreadEx),
    XBE_EXPORT(256, PsQueryStatistics),
    XBE_EXPORT(257, PsSetCreateThreadNotifyRoutine),
    XBE_EXPORT(258, PsTerminateSystemThread),
    XBE_EXPORT(259, PsThreadObjectType),
    XBE_EXPORT(260, RtlAnsiStringToUnicodeString),
    XBE_EXPORT(261, RtlAppendStringToString),
    XBE_EXPORT(262, RtlAppendUnicodeStringToString),
    XBE_EXPORT(263, RtlAppendUnicodeToString),
    XBE_EXPORT(264, RtlAssert),
    XBE_EXPORT(265, RtlCaptureContext),
    XBE_EXPORT(266, RtlCaptureStackBackTrace),
    XBE_EXPORT(267, RtlCharToInteger),
    XBE_EXPORT(268, RtlCompareMemory),
    XBE_EXPORT(269, RtlCompareMemoryUlong),
    XBE_EXPORT(270, RtlCompareString),
    XBE_EXPORT(271, RtlCompareUnicodeString),
    XBE_EXPORT(272, RtlCopyString),
    XBE_EXPORT(273, RtlCopyUnicodeString),
    XBE_EXPORT(274, RtlCreateUnicodeString),
    XBE_EXPORT(275, RtlDowncaseUnicodeChar),
    XBE_EXPORT(276, RtlDowncaseUnicodeString),
    XBE_EXPORT(277, RtlEnterCriticalSection),
    XBE_EXPORT(278, RtlEnterCriticalSectionAndRegion),
    XBE_EXPORT(279, RtlEqualString),
    XBE_EXPORT(280, RtlEqualUnicodeString),
    XBE_EXPORT(281, RtlExtendedIntegerMultiply),
    XBE_EXPORT(282, RtlExtendedLargeIntegerDivide),
    XBE_EXPORT(283, RtlExtendedMagicDivide),
    XBE_EXPORT(284, RtlFillMemory),
    XBE_EXPORT(285, RtlFillMemoryUlong),
    XBE_EXPORT(286, RtlFreeAnsiString),
    XBE_EXPORT(287, RtlFreeUnicodeString),
    XBE_EXPORT(288, RtlGetCallersAddress),
    XBE_EXPORT(289, RtlInitAnsiString),
    XBE_EXPORT(290, RtlInitUnicodeString),
    XBE_EXPORT(291, RtlInitializeCriticalSection),
    XBE_EXPORT(292, RtlIntegerToChar),
    XBE_EXPORT(293, RtlIntegerToUnicodeString),
    XBE_EXPORT(294, RtlLeaveCriticalSection),
    XBE_EXPORT(295, RtlLeaveCriticalSectionAndRegion),
    XBE_EXPORT(296, RtlLowerChar),
    XBE_EXPORT(297, RtlMapGenericMask),
    XBE_EXPORT(298, RtlMoveMemory),
    XBE_EXPORT(299, RtlMultiByteToUnicodeN),
    XBE_EXPORT(300, RtlMultiByteToUnicodeSize),
    XBE_EXPORT(301, RtlNtStatusToDosError),
    XBE_EXPORT(302, RtlRaiseException),
    XBE_EXPORT(303, RtlRaiseStatus),
    XBE_EXPORT(304, RtlTimeFieldsToTime),
    XBE_EXPORT(305, RtlTimeToTimeFields),
    XBE_EXPORT(306, RtlTryEnterCriticalSection),
    XBE_EXPORT(307, RtlUlongByteSwap),
    XBE_EXPORT(308, RtlUnicodeStringToAnsiString),
    XBE_EXPORT(309, RtlUnicodeStringToInteger),
    XBE_EXPORT(310, RtlUnicodeToMultiByteN),
    XBE_EXPORT(311, RtlUnicodeToMultiByteSize),
    XBE_EXPORT(312, RtlUnwind),
    XBE_EXPORT(313, RtlUpcaseUnicodeChar),
    XBE_EXPORT(314, RtlUpcaseUnicodeString),
    XBE_EXPORT(315, RtlUpcaseUnicodeToMultiByteN),
    XBE_EXPORT(316, RtlUpperChar),
    XBE_EXPORT(317, RtlUpperString),
    XBE_EXPORT(318, RtlUshortByteSwap),
    XBE_EXPORT(319, RtlWalkFrameChain),
    XBE_EXPORT(320, RtlZeroMemory),
    XBE_EXPORT(321, XboxEEPROMKey),
    XBE_EXPORT(322, XboxHardwareInfo),
    XBE_EXPORT(323, XboxHDKey),
    XBE_EXPORT(324, XboxKrnlVersion),
    XBE_EXPORT(325, XboxSignatureKey),
    XBE_EXPORT(326, XeImageFileName),
    XBE_EXPORT(327, XeLoadSection),
    XBE_EXPORT(328, XeUnloadSection),
    XBE_EXPORT(329, READ_PORT_BUFFER_UCHAR),
    XBE_EXPORT(330, READ_PORT_BUFFER_USHORT),
    XBE_EXPORT(331, READ_PORT_BUFFER_ULONG),
    XBE_EXPORT(332, WRITE_PORT_BUFFER_UCHAR),
    XBE_EXPORT(333, WRITE_PORT_BUFFER_USHORT),
    XBE_EXPORT(334, WRITE_PORT_BUFFER_ULONG),
    XBE_EXPORT(335, XcSHAInit),
    XBE_EXPORT(336, XcSHAUpdate),
    XBE_EXPORT(337, XcSHAFinal),
    XBE_EXPORT(338, XcRC4Key),
    XBE_EXPORT(339, XcRC4Crypt),
    XBE_EXPORT(340, XcHMAC),
    XBE_EXPORT(341, XcPKEncPublic),
    XBE_EXPORT(342, XcPKDecPrivate),
    XBE_EXPORT(343, XcPKGetKeyLen),
    XBE_EXPORT(344, XcVerifyPKCS1Signature),
    XBE_EXPORT(345, XcModExp),
    XBE_EXPORT(346, XcDESKeyParity),
    XBE_EXPORT(347, XcKeyTable),
    XBE_EXPORT(348, XcBlockCrypt),
    XBE_EXPORT(349, XcBlockCryptCBC),
    XBE_EXPORT(350, XcCryptService),
    XBE_EXPORT(351, XcUpdateCrypto),
    XBE_EXPORT(352, RtlRip),
    XBE_EXPORT(353, XboxLANKey),
    XBE_EXPORT(354, XboxAlternateSignatureKeys),
    XBE_EXPORT(355, XePublicKeyData),
    XBE_EXPORT(356, HalBootSMCVideoMode),
    XBE_EXPORT(357, IdexChannelObject),
    XBE_EXPORT(358, HalIsResetOrShutdownPending),
    XBE_EXPORT(359, IoMarkIrpMustComplete),
    XBE_EXPORT(360, HalInitiateShutdown),
    XBE_EXPORT(361, RtlSnprintf),
    XBE_EXPORT(362, RtlSprintf),
    XBE_EXPORT(363, RtlVsnprintf),
    XBE_EXPORT(364, RtlVsprintf),
    XBE_EXPORT(365, HalEnableSecureTrayEject),
    XBE_EXPORT(366, HalWriteSMCScratchRegister),
    // Higher ordinals for debug builds
    XBE_EXPORT(374, MmDbgAllocateMemory),
    XBE_EXPORT(375, MmDbgFreeMemory),
    XBE_EXPORT(376, MmDbgQueryAvailablePages),
    XBE_EXPORT(377, MmDbgReleaseAddress),
    XBE_EXPORT(378, MmDbgWriteCheck),
};

static const char* XbeGetKernelExportName(uint32_t ordinal)
{
    for (const auto& exp : g_xboxkrnlExports)
    {
        if (exp.first == ordinal)
        {
            return exp.second;
        }
    }
    return nullptr;
}

std::string XbeGetTitleName(const XbeCertificate* cert)
{
    std::string result;
    result.reserve(40);
    
    for (int i = 0; i < 40 && cert->titleName[i] != 0; i++)
    {
        // Simple Unicode to ASCII conversion (just take low byte)
        char c = static_cast<char>(cert->titleName[i] & 0xFF);
        result.push_back(c);
    }
    
    return result;
}

Image XbeLoadImage(const uint8_t* data, size_t size)
{
    const auto* header = reinterpret_cast<const XbeHeader*>(data);
    
    // Validate magic
    if (header->magic != XBE_MAGIC)
    {
        fmt::println("ERROR: Invalid XBE magic");
        return {};
    }
    
    Image image{};
    image.base = header->baseAddress;
    image.size = header->imageSize;
    
    // Allocate image data
    image.data = std::make_unique<uint8_t[]>(header->imageSize);
    memset(image.data.get(), 0, header->imageSize);
    
    // Copy headers to image
    memcpy(image.data.get(), data, header->headersSize);
    
    // Decrypt entry point (try retail key first, then debug)
    uint32_t entryPoint = header->entryPoint ^ XBE_ENTRY_POINT_RETAIL_KEY;
    if (entryPoint < header->baseAddress || entryPoint >= header->baseAddress + header->imageSize)
    {
        // Try debug key
        entryPoint = header->entryPoint ^ XBE_ENTRY_POINT_DEBUG_KEY;
    }
    image.entry_point = entryPoint;
    
    // Decrypt kernel thunk address
    uint32_t kernelThunkAddr = header->kernelThunkAddress ^ XBE_KERNEL_THUNK_RETAIL_KEY;
    if (kernelThunkAddr < header->baseAddress || kernelThunkAddr >= header->baseAddress + header->imageSize)
    {
        // Try debug key
        kernelThunkAddr = header->kernelThunkAddress ^ XBE_KERNEL_THUNK_DEBUG_KEY;
    }
    
    // Get certificate for title info
    const auto* cert = reinterpret_cast<const XbeCertificate*>(
        data + (header->certificateAddress - header->baseAddress));
    
    std::string titleName = XbeGetTitleName(cert);
    fmt::println("XBE Title: {}", titleName);
    fmt::println("XBE Title ID: 0x{:08X}", cert->titleId);
    fmt::println("XBE Base Address: 0x{:08X}", header->baseAddress);
    fmt::println("XBE Entry Point: 0x{:08X}", entryPoint);
    fmt::println("XBE Kernel Thunk: 0x{:08X}", kernelThunkAddr);
    fmt::println("XBE Section Count: {}", header->sectionCount);
    
    // Get section headers
    const auto* sectionHeaders = reinterpret_cast<const XbeSectionHeader*>(
        data + (header->sectionHeadersAddress - header->baseAddress));
    
    // Load sections
    for (uint32_t i = 0; i < header->sectionCount; i++)
    {
        const auto& section = sectionHeaders[i];
        
        // Get section name
        const char* sectionName = reinterpret_cast<const char*>(
            data + (section.sectionNameAddress - header->baseAddress));
        
        // Calculate RVA relative to image base
        uint32_t rva = section.virtualAddress - header->baseAddress;
        
        // Determine section flags
        uint8_t flags = 0;
        
        // Check for executable flag from XBE, but also verify by section name
        // Some XBEs have incorrect flags set on data sections
        bool isExecutable = (section.flags & XBE_SECTION_EXECUTABLE) != 0;
        
        // Override based on known section names
        // The XBE format has many game-specific sections. We use name heuristics
        // since the executable flag in the section header is often unreliable.
        if (sectionName)
        {
            // Known CODE sections (always executable)
            // .text is standard code, others are Xbox SDK library code
            if (strncmp(sectionName, ".text", 5) == 0 ||
                strncmp(sectionName, "CODE", 4) == 0 ||
                strncmp(sectionName, ".code", 5) == 0 ||
                strncmp(sectionName, "DSOUND", 6) == 0 ||     // DirectSound library code
                strncmp(sectionName, "D3D", 3) == 0 ||        // Direct3D library code
                strncmp(sectionName, "XONLINE", 7) == 0 ||    // Xbox Online library code
                strncmp(sectionName, "XNET", 4) == 0 ||       // Xbox Network library code
                strncmp(sectionName, "XGRPH", 5) == 0 ||      // Xbox Graphics library code
                strncmp(sectionName, "XPP", 3) == 0 ||        // Xbox presence library code
                strncmp(sectionName, "WMADEC", 6) == 0 ||     // WMA decoder library code
                strncmp(sectionName, "BINK", 4) == 0 ||       // Bink video library code
                strncmp(sectionName, "DMUSIC", 6) == 0)       // DirectMusic library code
            {
                isExecutable = true;
            }
            // Known DATA sections (never executable)
            // Standard PE/COFF data sections and Xbox-specific data sections
            else if (strncmp(sectionName, ".rdata", 6) == 0 ||
                     strncmp(sectionName, ".data", 5) == 0 ||
                     strncmp(sectionName, ".bss", 4) == 0 ||
                     strncmp(sectionName, ".rsrc", 5) == 0 ||
                     strncmp(sectionName, ".reloc", 6) == 0 ||
                     strncmp(sectionName, ".idata", 6) == 0 ||
                     strncmp(sectionName, ".edata", 6) == 0 ||
                     strncmp(sectionName, "RDATA", 5) == 0 ||
                     strncmp(sectionName, "DATA", 4) == 0 ||
                     strncmp(sectionName, "BSS", 3) == 0 ||
                     // Xbox-specific DATA sections
                     strncmp(sectionName, "DOLBY", 5) == 0 ||      // Dolby Digital audio coefficients/data
                     strncmp(sectionName, "XON_RD", 6) == 0 ||     // Xbox Online read-only data
                     strncmp(sectionName, "$$XSIMAGE", 9) == 0 ||  // Xbox image resource data
                     strncmp(sectionName, "$$XTIMAGE", 9) == 0 ||  // Xbox image resource data
                     strncmp(sectionName, "$$XTIMAG", 8) == 0 ||   // Xbox image resource data
                     strncmp(sectionName, "XBOXKRNL", 8) == 0 ||   // Kernel import table data
                     strncmp(sectionName, "EFFDATA", 7) == 0)      // Effect/resource data
            {
                isExecutable = false;
            }
        }
        
        if (isExecutable)
        {
            flags |= SectionFlags_Code;
        }
        
        // Copy section data to image
        if (section.rawSize > 0 && section.rawAddress > 0)
        {
            // Ensure we don't overflow
            size_t copySize = std::min(static_cast<size_t>(section.rawSize), 
                                       static_cast<size_t>(section.virtualSize));
            if (rva + copySize <= header->imageSize)
            {
                memcpy(image.data.get() + rva, data + section.rawAddress, copySize);
            }
        }
        
        // Map section
        image.Map(sectionName, rva, section.virtualSize, flags, image.data.get() + rva);
        
        fmt::println("  Section '{}': VA=0x{:08X}, Size=0x{:X}, Flags=0x{:X}", 
                     sectionName, section.virtualAddress, section.virtualSize, section.flags);
    }
    
    // Parse kernel thunk table and add symbols
    const uint32_t* thunkTable = reinterpret_cast<const uint32_t*>(
        image.data.get() + (kernelThunkAddr - header->baseAddress));
    
    for (size_t i = 0; thunkTable[i] != 0; i++)
    {
        uint32_t thunkValue = thunkTable[i];
        
        // Check if this is an ordinal import (high bit set)
        if (thunkValue & 0x80000000)
        {
            uint32_t ordinal = thunkValue & 0x7FFFFFFF;
            const char* exportName = XbeGetKernelExportName(ordinal);
            
            if (exportName)
            {
                // Add symbol for the thunk entry
                uint32_t thunkEntryAddr = kernelThunkAddr + static_cast<uint32_t>(i * sizeof(uint32_t));
                image.symbols.emplace(exportName, thunkEntryAddr, 4, Symbol_Function);
            }
        }
    }
    
    fmt::println("Loaded {} kernel import symbols", image.symbols.size());
    
    return image;
}
