#pragma once

// Definitions below are shared across both the "encode" and "decode" APIs.

// Arguments for "cs_open".
struct CapstoneOpenArgs
{
    cs_arch m_arch;
    cs_mode m_mode;
};

const std::unordered_map< std::string_view, CapstoneOpenArgs > g_cs_args{
    // x86.
    { "x86-64", { CS_ARCH_X86, CS_MODE_64 } }, // x86 (64-bit).
    { "x86-32", { CS_ARCH_X86, CS_MODE_32 } }, // x86 (32-bit).
    { "x86-16", { CS_ARCH_X86, CS_MODE_16 } }, // x86 (16-bit).

    // ARM.
    { "aarch64", { CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN } } // ARM-64 (aka. AArch64); NOTE: Keystone doesn't support big endian ARM64 but Capstone does.
};

// API route handlers.
#include "api_encode.hpp"