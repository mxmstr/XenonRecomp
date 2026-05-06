project("XBERecomp")

set(LIB86CPU_ROOT ${THIRDPARTY_ROOT}/lib86cpu-repo)

add_executable(XBERecomp
    "main.cpp"
    "recompiler.cpp"
    "recompiler_config.cpp"
    "../XBEAnalyse/xbe.cpp"
)

target_include_directories(XBERecomp
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../XBEAnalyse
        ${LIB86CPU_ROOT}/include
        ${LIB86CPU_ROOT}/lib86cpu
        ${LIB86CPU_ROOT}/lib86cpu/core
        ${LIB86CPU_ROOT}/import/zydis/include
        ${LIB86CPU_ROOT}/import/zydis/dependencies/zycore/include
        ${CMAKE_BINARY_DIR}/thirdparty/lib86cpu-repo/import/zydis
        ${CMAKE_BINARY_DIR}/thirdparty/lib86cpu-repo/import/zydis/zycore
)

target_link_libraries(XBERecomp
    PRIVATE
        XenonUtils
        fmt::fmt
        tomlplusplus::tomlplusplus
        xxHash::xxhash
        cpu
        Zydis
)

target_compile_definitions(XBERecomp PRIVATE _CRT_SECURE_NO_WARNINGS)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(XBERecomp PRIVATE -Wno-switch -Wno-unused-variable)
endif()
