// ==============================================================================
// ObFUSEcate
// fileio.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include "fileio.hpp"
#include <unistd.h>
#include <system_error>

namespace fileio
{

void write(int fd, const uint8_t* ptr, size_t nbytes, uint64_t offset)
{
    if (nbytes == 0)
    {
        return;
    }

    size_t total_written = 0;
    do
    {
        ssize_t written = pwrite(fd, ptr + total_written, nbytes - total_written, static_cast<__off64_t>(offset + total_written));
        if (written > 0)
        {
            total_written += static_cast<size_t>(written);
        }
        else if (errno != EINTR)
        {
            throw std::system_error(errno, std::generic_category(), "POSIX I/O failed: pwrite()");
        }
    } while (total_written < nbytes);
}

void read(int fd, uint8_t* ptr, size_t nbytes, uint64_t offset)
{
    if (nbytes == 0)
    {
        return;
    }

    size_t total_read = 0;
    do
    {
        ssize_t nread = pread(fd, ptr + total_read, nbytes - total_read, static_cast<__off64_t>(offset + total_read));
        if (nread > 0)
        {
            total_read += static_cast<size_t>(nread);
        }
        else if (nread == 0)
        {
            throw std::runtime_error("Unexpected EOF during pread()");
        }
        else if (errno != EINTR)
        {
            throw std::system_error(errno, std::generic_category(), "POSIX I/O failed: pread()");
        }
    } while (total_read < nbytes);
}

void writev(int fd, struct iovec* iov, int iovcnt, uint64_t offset)
{
    size_t total_to_write = 0;
    for (int i = 0; i < iovcnt; ++i)
    {
        total_to_write += iov[i].iov_len;
    }

    size_t total_written = 0;
    while (total_written < total_to_write)
    {
        ssize_t written = pwritev(fd, iov, iovcnt, static_cast<__off64_t>(offset + total_written));
        
        if (written > 0)
        {
            total_written += static_cast<size_t>(written);
            size_t w = static_cast<size_t>(written);
            
            // Advance the iovec array to account for the bytes just written
            while (w > 0 && iovcnt > 0)
            {
                if (w >= iov[0].iov_len)
                {
                    w -= iov[0].iov_len;
                    iov++;     // shift array pointer forward
                    iovcnt--;  // decrement remaining vectors
                }
                else
                {
                    // partial write landed in the middle of this specific vector
                    iov[0].iov_base = static_cast<uint8_t*>(iov[0].iov_base) + w;
                    iov[0].iov_len -= w;
                    w = 0;
                }
            }
        }
        else if (errno != EINTR)
        {
            throw std::system_error(errno, std::generic_category(), "POSIX I/O failed: pwritev()");
        }
    }
}

} // namespace fileio
