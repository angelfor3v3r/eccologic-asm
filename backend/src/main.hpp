#pragma once

// Shorthands.
#ifdef _MSC_VER
#define ATTR_FORCEINLINE [[msvc::forceinline]]
#else
#define ATTR_FORCEINLINE [[gnu::always_inline]]
#endif

// STL includes.
#include <cstdint>
#include <string>
#include <unordered_map>
#include <iostream>
#include <format>

// Dependency includes.
#include "scope_guard/scope_guard.hpp"
#include "drogon/drogon.h"
#include "keystone/keystone.h"
#include "capstone/capstone.h"

// Other includes.
#include "api.hpp"