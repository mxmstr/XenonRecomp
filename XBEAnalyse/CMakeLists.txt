project("XBEAnalyse")

set(LIB86CPU_ROOT ${THIRDPARTY_ROOT}/lib86cpu-repo)

add_executable(XBEAnalyse
    "main.cpp"
    "xbe.cpp"
)

target_include_directories(XBEAnalyse
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LIB86CPU_ROOT}/import/zydis/include
        ${LIB86CPU_ROOT}/import/zydis/dependencies/zycore/include
        ${CMAKE_BINARY_DIR}/thirdparty/lib86cpu-repo/import/zydis
        ${CMAKE_BINARY_DIR}/thirdparty/lib86cpu-repo/import/zydis/zycore
)

target_link_libraries(XBEAnalyse
    PRIVATE
        XenonUtils
        fmt::fmt
        Zydis
)
