// ==============================================================================
// ObFUSEcate
// crypto.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: Miscellaneous cryptography utility functions
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <cstddef>
#include <cstdint>

namespace crypto
{
// zero out a memory block    
void zero_memory(uint8_t* ptr, size_t len);

// pin memory to avoid paging out or being dumped in crash data
void armor_memory(void* ptr, size_t size);

// unpin memory
void dearmor_memory(void* ptr, size_t size);

} // namespace crypto
