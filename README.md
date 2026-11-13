# ObFUSEcate
**Opaque Block Filesystem Using Strong Encryption, Compression, and Tolerant Encoding**

**ObFUSEcate** is a zero-dependency (aside from `libfuse3`), userspace virtual block device written in C++ that provides authenticated encryption, adaptive compression, sparse thin-provisioning, and automatic bit-rot recovery. Mounted entirely in userspace via [FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) and `fuse2fs`, it exposes a standard `ext4` filesystem backed by a single opaque container file—requiring **no root privileges** or kernel modules.

## Key Features

* **Authenticated Encryption (RFC 8439 ChaCha20-Poly1305):** Every 16 KB logical block, is encrypted and authenticated with unique nonces and block-index Associated Authenticated Data (AAD) to prevent block-swapping, tampering, and offline modification.
* **Metadata & Directory Obfuscation:** Unlike file-level overlay encryptors ([gocryptfs](https://github.com/rfjakob/gocryptfs), [EncFS](https://github.com/vgough/encfs)) that expose directory trees, file counts, and per-file sizes on the host filesystem, an ObFUSEcate volume is a single flat container file.
* **Transparent Block Compression:** Payloads are compressed prior to encryption using a 32-bit arithmetic coder. Incompressible blocks bypass compression to prevent expansion.
* **Sparse Thin-Provisioning:** Creating a 10 GB volume only consumes a few kilobytes on disk. Unwritten and zero-filled blocks consume zero physical storage, and deleted files are reclaimed on unmount via `zerofree`.
* **Self-Healing Error Correction (ECC):** Each encrypted block is striped into 128-byte shards protected by CRC-8 checksums and an XOR parity shard, allowing transparent recovery from single-shard disk corruption or bit-rot prior to cryptographic verification.
* **Memory Hardening:** Cryptographic keys are pinned in non-swappable RAM (`mlock`), excluded from core dumps (`MADV_DONTDUMP`), protected against `ptrace` inspection (`PR_SET_DUMPABLE`), and deterministically zeroed on exit.

## Comparison to Similar Systems

| Feature | EncFS / gocryptfs | LUKS (`dm-crypt`) | ObFUSEcate |
| :--- | :--- | :--- | :--- |
| **Granularity** | File-level overlay | Block device | Block device |
| **Hides File Count & Tree** | No | Yes | Yes |
| **Requires Root (`sudo`)** | No | Yes | No |
| **Thin-Provisioned / Sparse** | Yes | No | Yes |
| **Built-in ECC / Bit-Rot Repair** | No | No | Yes |

## What ObFUSEcate Isn't

ObFUSEcate is designed for portable, high-integrity secure vaults (e.g., sensitive documents, credentials, source repositories) rather than high-throughput bulk media storage or full-disk OS encryption. Because every block transitions through userspace FUSE, arithmetic coding, software ChaCha20-Poly1305, and dynamic block relocation, I/O throughput is intentionally traded for compactness, self-contained portability, and bit-level resilience.

## Installation

### Prerequisites

Building requires a C++17 compiler, CMake, and **libfuse3-dev**. Running the mount helper script requires **fuse2fs** and (optionally) **zerofree** for automatic free-space compaction on unmount.

On Ubuntu/Debian systems:

```bash
sudo apt update && sudo apt install build-essential cmake libfuse3-dev fuse3 fuse2fs zerofree
```

### Build & Install

```bash
git clone https://github.com/tgaloppo/obfusecate.git
cd obfusecate
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build -j$(nproc)
sudo cmake --install build
```

*(Note: You can specify a local prefix such as `-DCMAKE_INSTALL_PREFIX=$HOME/.local` to install without root privileges.)*

## Usage

The `obfusecate` wrapper script handles two-stage FUSE mounting (mounting the raw encrypted block device to a hidden bridge directory and mounting an unjournaled `ext4` filesystem on top via `fuse2fs`).

### 1. Create and Format a New Volume

To create a thin-provisioned 1 GB volume in `my_volume.ofs` and mount it at `~/secure_mount`:

```bash
obfusecate format my_volume.ofs ~/secure_mount 1G
```

*Note: Physical disk usage starts near zero and grows dynamically up to the 1 GB logical limit as data is written.*

### 2. Mount an Existing Volume

```bash
obfusecate mount my_volume.ofs ~/secure_mount
```

### 3. Unmount a Volume

```bash
obfusecate umount ~/secure_mount
```

During unmount, if [zerofree](https://www.kali.org/tools/zerofree/) is installed, unused `ext4` blocks are automatically zeroed and compacted out of the backing `.ofs` file.

### Passwords and Key Files

By default, `obfusecate` prompts interactively for a passphrase. Alternatively, you can supply a 32-byte (256-bit) binary keyfile:

```bash
# Generate a 256-bit cryptographically random keyfile
head -c 32 /dev/urandom > my_key.key
chmod 600 my_key.key

# Or derive a 32-byte keyfile from a passphrase
printf '%s' "my secret passphrase" | sha256sum | awk '{print $1}' | xxd -r -p > my_key.key
chmod 600 my_key.key
```

Pass the keyfile as the final argument when formatting or mounting:

```bash
obfusecate format my_vol.ofs ~/secure 1G my_key.key
obfusecate mount  my_vol.ofs ~/secure my_key.key
```
