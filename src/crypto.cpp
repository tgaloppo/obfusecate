// ==============================================================================
// ObFUSEcate
// crypto.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include "crypto.hpp"

#include <unistd.h>
#include <sys/mman.h>

namespace crypto
{

void zero_memory(uint8_t* data, std::size_t length)
{
    volatile uint8_t* ptr = data;
    for (std::size_t j = 0; j < length; j++)
    {
        *(ptr++) = 0;
    }
}

void armor_memory(void* ptr, size_t size)
{
    // Cast to unsigned immediately to ensure safe bitwise arithmetic
    uintptr_t page_size = static_cast<uintptr_t>(::sysconf(_SC_PAGESIZE));
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = (addr - aligned_addr) + size;
    void* lock_ptr = reinterpret_cast<void*>(aligned_addr);

    ::mlock(lock_ptr, aligned_size);
    ::madvise(lock_ptr, aligned_size, MADV_DONTDUMP);
}

void dearmor_memory(void* ptr, size_t size)
{
    uintptr_t page_size = static_cast<uintptr_t>(::sysconf(_SC_PAGESIZE));
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = (addr - aligned_addr) + size;
    void* lock_ptr = reinterpret_cast<void*>(aligned_addr);

    // Explicitly cast void* to uint8_t* for zero_memory
    crypto::zero_memory(static_cast<uint8_t*>(ptr), size); 
    ::madvise(lock_ptr, aligned_size, MADV_DODUMP);
    ::munlock(lock_ptr, aligned_size);
}

} // namespace crypto
