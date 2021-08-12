set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

if(UNIX)
    set(VCPKG_CMAKE_SYSTEM_NAME Linux)
endif()

if(${PORT} MATCHES "mimalloc")
    set(VCPKG_LIBRARY_LINKAGE dynamic)
endif()