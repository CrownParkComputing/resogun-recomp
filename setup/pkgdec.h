// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// The AES-128-XTS decryption of a PS4 PFS image (setup/pkgdec.cpp): the game data in a .pkg is
// encrypted, and decrypting 700 MB in Python would take hours, so this is native code the
// extractor (scripts/pkg_extract.py) calls.

#include <filesystem>
#include <string>
#include <vector>

namespace setup {

// Decrypts one XTS sector of `sector` (0x1000 bytes) in place: the tweak is the sector's number,
// the data key decrypts the blocks and the tweak key encrypts the tweak.
void xts_decrypt_sector(const unsigned char* data_key, const unsigned char* tweak_key,
                        unsigned long long sector_index, unsigned char* sector);

// Decrypts the PFS image at `offset` in `pkg` (pfs_length bytes) into `out`: the sectors before
// `first_encrypted` are copied as they are, the rest are decrypted. Throws Error.
void decrypt_pfs_image(const std::filesystem::path& pkg, unsigned long long offset,
                        unsigned long long pfs_length, unsigned long long first_encrypted,
                        const std::string& data_key_hex, const std::string& tweak_key_hex,
                        const std::filesystem::path& out);

// The mode the setup runs as when the extractor asks it to: --pkg-decrypt <pkg> <offset> <length>
// <out> <data-key-hex> <tweak-key-hex> <first-encrypted-sector>. Returns the exit code.
int pkg_decrypt_main(const std::vector<std::wstring>& args);

} // namespace setup
