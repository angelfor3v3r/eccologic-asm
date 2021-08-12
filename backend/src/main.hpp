#pragma once

// STL includes.
#include <cstdint>
#include <string>
#include <unordered_map>
#include <iostream>
#include <type_traits>
#include <utility>
#include <concepts>

// Dependency includes (2).
#include "fmt/format.h"
#include "drogon/drogon.h"
#include "keystone/keystone.h"
#include "capstone/capstone.h"

// App includes.
#include "mimalloc.h"
#include "scope_guard.hpp"
#include "api.hpp"