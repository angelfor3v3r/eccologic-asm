#pragma once

// STL includes.
#include <cstdint>
#include <string>
#include <unordered_map>
#include <iostream>
#include <type_traits>
#include <utility>
#include <concepts>
#include <regex>

// Dependency includes (2).
#include "mimalloc.h"
#include "fmt/format.h"
#include "drogon/drogon.h"
#include "keystone/keystone.h"
#include "capstone/capstone.h"

using namespace drogon;

// App includes.
#include "scope_guard.hpp"
#include "api.hpp"