cmake_minimum_required(VERSION 3.20)

# Test for Vcpkg toolchain... If CMAKE_TOOLCHAIN_FILE isn't set and then test if it's set from an env var.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VCPKG_ROOT})
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
    else()
        message(FATAL_ERROR
            "Eccologic ASM requires Vcpkg. "
            "Please pass the Vcpkg toolchain with \"CMAKE_TOOLCHAIN_FILE\" or set the environment variable \"VCPKG_ROOT\" to the Vcpkg install directory.")
    endif()
endif()

# Use the custom triplet for Vcpkg.
set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_SOURCE_DIR}/triplets")
set(VCPKG_TARGET_TRIPLET "x64-mixed")

project(asm
    VERSION 1.0.0
    HOMEPAGE_URL "https://asm.eccologic.net/"
    LANGUAGES CXX)

# 32-bit isn't supported (sorry not sorry)!
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Eccologic ASM requires a 64-bit CPU.")
endif()

find_package(mimalloc 1.6.4 CONFIG REQUIRED)
find_package(Drogon CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_library(KEYSTONE_LIB keystone REQUIRED)
find_library(CAPSTONE_LIB capstone REQUIRED)

# Source files are relative to "./src".
set(SRC_FILES
    api_encode.cpp
    main.cpp)
list(TRANSFORM SRC_FILES PREPEND "src/")
add_executable(${PROJECT_NAME} ${SRC_FILES})

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

target_include_directories(${PROJECT_NAME} PRIVATE "src/")

target_link_libraries(${PROJECT_NAME} PRIVATE
    mimalloc
    fmt::fmt-header-only
    Drogon::Drogon
    ${KEYSTONE_LIB}
    ${CAPSTONE_LIB})

set(BIN_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/../bin")
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${BIN_OUTPUT_PATH})

    target_compile_options(${PROJECT_NAME} PRIVATE /Zc:__cplusplus /O2 /Gw /GL /MD)
    target_link_options(${PROJECT_NAME} PRIVATE /LTCG /INCREMENTAL:NO /OPT:REF /OPT:ICF=2 /DEBUG:NONE)
else()
    set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${BIN_OUTPUT_PATH})
    target_compile_options(${PROJECT_NAME} PRIVATE -O2 -fmerge-all-constants -g0 -fno-ident -fomit-frame-pointer)
endif()

# Copy the default config file for drogon.
configure_file(drogon-config.json.default "${BIN_OUTPUT_PATH}/drogon-config.json" @ONLY)

# On Unix we need this file from mimalloc to LDPRELOAD with it. I'm not sure how else to have Vcpkg/CMake put this file in my "bin" folder.
if(UNIX)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib/libmimalloc.so.${mimalloc_VERSION}" "${BIN_OUTPUT_PATH}/libmimalloc.so")
endif()