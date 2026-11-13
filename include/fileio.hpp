// ==============================================================================
// ObFUSEcate
// fileio.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: Wrappers for POSIX pread / pwrite / pwritev functions
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/uio.h>

namespace fileio
{
    
// wrap POSIX read/write in more useful packages
void read(int fd, uint8_t*, size_t, uint64_t);
void write(int fd, const uint8_t*, size_t, uint64_t);
void writev(int fd, struct iovec* iov, int iovcnt, uint64_t offset);

} // namespace fileio
