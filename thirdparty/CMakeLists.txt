add_subdirectory(${THIRDPARTY_ROOT}/disasm)

if (NOT TARGET fmt::fmt)
    add_subdirectory(${THIRDPARTY_ROOT}/fmt)
endif()

if (NOT TARGET tomlplusplus::tomlplusplus)
    add_subdirectory(${THIRDPARTY_ROOT}/tomlplusplus)
endif()

if (NOT TARGET xxHash::xxhash)
    add_subdirectory(${THIRDPARTY_ROOT}/xxHash/cmake_unofficial)
endif()

if (NOT TARGET cpu)
    option(LIB86CPU_XBOX_BUILD "Build an xbox-customized version of lib86cpu" ON)
    option(LIB86CPU_BUILD_TEST "Build lib86cpu test app" OFF)
    add_subdirectory(${THIRDPARTY_ROOT}/lib86cpu-repo)
endif()
