// ==============================================================================
// ObFUSEcate
// main.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: Interface between FUSE and virtual block device
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sys/prctl.h>
#include "block_device.hpp"
#include "crypto.hpp"

static constexpr const char* VOLUME_FILE_PATH = "/data";

static obfusecate::block_device* get_device()
{
    return static_cast<obfusecate::block_device*>(fuse_get_context()->private_data);
}

static int device_getattr(const char* path, struct stat* stbuf, [[maybe_unused]] struct fuse_file_info* fi)
{
    std::memset(stbuf, 0, sizeof(struct stat));

    if (std::strcmp(path, "/") == 0)
    {
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    else if (std::strcmp(path, VOLUME_FILE_PATH) == 0)
    {
        stbuf->st_mode    = S_IFREG | 0666;
        stbuf->st_nlink   = 1;
        stbuf->st_size    = static_cast<__off_t>(get_device()->get_logical_size());
        stbuf->st_blksize = static_cast<__blksize_t>(get_device()->get_logical_block_size());
        return 0;
    }

    return -ENOENT;
}

static int device_readdir(const char* path, void* buf, fuse_fill_dir_t filler, [[maybe_unused]] off_t offset, [[maybe_unused]] struct fuse_file_info* fi, [[maybe_unused]] enum fuse_readdir_flags flags)
{
    if (std::strcmp(path, "/") != 0)
    {
        return -ENOENT;
    }

    filler(buf, ".",  NULL, 0, static_cast<fuse_fill_dir_flags>(0));
    filler(buf, "..", NULL, 0, static_cast<fuse_fill_dir_flags>(0));
    filler(buf, VOLUME_FILE_PATH + 1, NULL, 0, static_cast<fuse_fill_dir_flags>(0));

    return 0;
}

static int device_open(const char *path, [[maybe_unused]] struct fuse_file_info *fi)
{
    if (std::strcmp(path, VOLUME_FILE_PATH) == 0)
    {
        return 0;
    }
    return -ENOENT;
}

static int device_truncate(const char *path, off_t size, [[maybe_unused]] struct fuse_file_info *fi)
{
    if (std::strcmp(path, VOLUME_FILE_PATH) != 0)
    {
        return -ENOENT;
    }
    try
    {
        get_device()->set_logical_size(static_cast<uint64_t>(size));
    }
    catch(...)
    {
        return -EIO;
    }
    
    return 0;
}

static int device_read(const char *path, char *buf, size_t size, off_t offset, [[maybe_unused]] struct fuse_file_info *fi)
{
    // make sure file path is correct
    if (std::strcmp(path, VOLUME_FILE_PATH) != 0)
    {
        return -ENOENT;
    }

    uint64_t offset_u64 = static_cast<uint64_t>(offset);

    // get the logical file size
    uint64_t file_size = get_device()->get_logical_size();

    // if offset is beyond end of file, return 0
    if (offset_u64 >= file_size)
    {
        return 0;
    }

    // truncate read length to file size
    size = std::min(size, static_cast<size_t>(file_size - offset_u64));

    // get the block size from the filesystem
    uint32_t block_size = get_device()->get_logical_block_size();

    // allocate buffer for block reads
    std::vector<uint8_t> read_buffer(block_size);

    // calculate index of starting block
    uint64_t block_index = offset_u64 / block_size;

    // calculate offset into block where requested data starts
    uint64_t offset_bytes = offset_u64 % block_size;

    // read until we fill requested size
    size_t bytes_remaining = size;
    size_t bytes_available = block_size - offset_bytes;

    while (bytes_remaining > 0)
    {
        // read block; may throw exception, which we must handle here
        try
        {
            get_device()->read_logical_block(block_index, read_buffer);
        }
        catch(...)
        {
            return -EIO;
        }
        // extract bytes from block
        size_t n_bytes = std::min(bytes_remaining, bytes_available);
        std::memcpy(buf + size - bytes_remaining, read_buffer.data() + offset_bytes, n_bytes);
        // update remaining count / prep for next block
        bytes_remaining -= n_bytes;
        block_index     += 1;
        offset_bytes    = 0;
        bytes_available = block_size;
    }

    return static_cast<int>(size);
}

static int device_write(const char *path, const char *buf, size_t size, off_t offset, [[maybe_unused]] struct fuse_file_info *fi)
{
    // check to make sure the path is correct
    if (std::strcmp(path, VOLUME_FILE_PATH) != 0)
    {
        return -ENOENT;
    }

    uint64_t offset_u64 = static_cast<uint64_t>(offset);

    // get block size and current block count
    uint32_t block_size  = get_device()->get_logical_block_size();
    uint64_t block_count = get_device()->get_block_count();

    // determine block offset of where to begin writing, and the
    // offset into the block at which to start writing
    uint64_t block_index  = offset_u64 / block_size;
    uint64_t offset_bytes = offset_u64 % block_size;

    // create buffer for block read/write
    std::vector<uint8_t> block_buffer(block_size);

    size_t remaining = size;

    while (remaining > 0)
    {
        // how many bytes to write this block
        size_t n_bytes = std::min(remaining, static_cast<size_t>(block_size - offset_bytes));

        // if we are not writing a full block, and this is not a new block, we need
        // to read the existing block first
        if (n_bytes < block_size) 
        {
            if (block_index < block_count)
            {
                try 
                {
                    get_device()->read_logical_block(block_index, block_buffer);
                }
                catch(...)
                {
                    return -EIO;
                }
            }
            else 
            {
                std::memset(block_buffer.data(), 0, block_size);
            }
        }

        // write n_bytes into this block starting at offset_bytes
        std::memcpy(block_buffer.data() + offset_bytes, buf + size - remaining, n_bytes);

        // write this block out
        try
        {
            get_device()->write_logical_block(block_index, block_buffer);
        }
        catch(...)
        {
            return -EIO;
        }

        // update remaining bytes and prepare for next block
        remaining   -= n_bytes;
        block_index += 1;
        offset_bytes = 0;
    }

    return static_cast<int>(size);
}

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        std::cout << "USAGE: " << argv[0] << " <device file> <key file> <mount point> [fuse options]" << std::endl;
        return 1;
    }

    // disable ptrace attachment
    if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to disable process dumpability");
    }

    crypto::chacha20::Key key;
    crypto::armor_memory(key.data(), key.size());

    // read key data from specified file
    std::ifstream key_file(argv[2], std::ios::binary);
    if (!key_file || !key_file.read(reinterpret_cast<char*>(key.data()), key.size()))
    {
        throw std::runtime_error("Failed to read key from keyfile.");
    }

    obfusecate::block_device _file(argv[1], key);

    // key is now handed off to the file manager; we can wipe 
    // the local copy and free the memory locks; note
    // memory lock will be unlocked upon _file destructor.
    crypto::zero_memory(key.data(), key.size());

    struct fuse_operations ops = {};
    ops.getattr  = device_getattr;
    ops.readdir  = device_readdir;
    ops.truncate = device_truncate;
    ops.open     = device_open;
    ops.read     = device_read;
    ops.write    = device_write;

    // skip arguments to obfusecate
    argv[2] = argv[0];

    // start the daemon
    return fuse_main(argc - 2, argv + 2, &ops, &_file);
}
