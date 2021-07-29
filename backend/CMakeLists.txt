cmake_minimum_required(VERSION 3.20)

# Test for Vcpkg toolchain... If CMAKE_TOOLCHAIN_FILE isn't set and then test if it's set from an env var.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VCPKG_ROOT})
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
    else()
        message(FATAL_ERROR
            "Eccologic-asm requires Vcpkg. "
            "Please pass the Vcpkg toolchain with \"CMAKE_TOOLCHAIN_FILE\" or set the environment variable \"VCPKG_ROOT\" to the Vcpkg install directory.")
    endif()
endif()

project(asm
    VERSION 1.0.0
    HOMEPAGE_URL "https://asm.eccologic.net/"
    LANGUAGES CXX)

find_package(mimalloc 1.6.4 CONFIG REQUIRED)
find_package(drogon CONFIG REQUIRED)
find_library(KEYSTONE_LIB keystone REQUIRED)
find_library(CAPSTONE_LIB capstone REQUIRED)

# Source files relative to "./src".
set(SRC_FILES
    api_encode.cpp
    main.cpp)
list(TRANSFORM SRC_FILES PREPEND "src/")
add_executable(${PROJECT_NAME} ${SRC_FILES})

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

target_include_directories(${PROJECT_NAME} PRIVATE "dependencies/" "src/")

target_link_libraries(${PROJECT_NAME} PRIVATE
    mimalloc-static
    Drogon::Drogon
    ${KEYSTONE_LIB}
    ${CAPSTONE_LIB})

set(BIN_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/../bin")
if(MSVC)
    # TODO: Test for MSVC_VERSION >= 1927

    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${BIN_OUTPUT_PATH})

    target_compile_options(${PROJECT_NAME} PRIVATE /Zc:__cplusplus /std:c++latest /Zi)
    target_link_options(${PROJECT_NAME} PRIVATE /INCREMENTAL:NO /OPT:REF /OPT:ICF=4 /DEBUG:FULL)
else()
    #set_target_properties(${PROJECT_NAME} PROPERTIES
    #    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    #    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    #    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()

# Copy the default config file for drogon (On windows we can't run as daemon).
if(WIN32)
    set(DROGON_CFG_RUN_AS_DAEMON false)
else()
    set(DROGON_CFG_RUN_AS_DAEMON true)
endif()
configure_file(drogon-config.json.default "${BIN_OUTPUT_PATH}/drogon-config.json" @ONLY)