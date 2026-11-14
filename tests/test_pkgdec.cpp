// SPDX-License-Identifier: GPL-2.0-or-later
// The AES-128 and the XTS of setup/pkgdec.cpp: the vector of FIPS-197 and the decryption of a
// sector, so a mistake in either does not come back unnoticed.
//
// The test includes the file itself: its AES lives in an anonymous namespace, and only the setup
// program needs it.
#include "../setup/pkgdec.cpp"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::printf("FAIL: %s\n", what);
        failures++;
    }
}

bool same(const unsigned char* got, const unsigned char* want, size_t size) {
    return memcmp(got, want, size) == 0;
}

} // namespace

int main() {
    // FIPS-197, appendix C.1: the first AES-128 vector.
    setup::Aes128 cipher;
    unsigned char key[16], plain[16], encrypted[16], decrypted[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (unsigned char)i;
        plain[i] = (unsigned char)(0x11 * i);
    }
    cipher.set_key(key);
    cipher.encrypt_block(plain, encrypted);
    const unsigned char expected[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    check(same(encrypted, expected, 16), "AES-128 encrypts the FIPS-197 vector");
    cipher.decrypt_block(encrypted, decrypted);
    check(same(decrypted, plain, 16), "AES-128 decrypts the FIPS-197 vector");

    // The XTS of the PS4's PFS images: a sector is 0x1000 bytes, the tweak of a sector is its
    // number in little endian, encrypted with the tweak key, and multiplied by alpha for every
    // 16-byte block in it.
    unsigned char data_key[16], tweak_key[16], sector[0x1000];
    for (int i = 0; i < 16; i++) {
        data_key[i] = (unsigned char)(0x10 + i);
        tweak_key[i] = (unsigned char)(0x20 + i);
    }
    for (int i = 0; i < 0x1000; i++)
        sector[i] = (unsigned char)(i * 7 + 3);
    struct {
        unsigned long long index;
        const char* first;
        const char* last;
    } vectors[] = {
        {0, "5a765000d9b2a0cf86369b98e7e44bc7",
            "44c09683c48ce76ec86df2dd97927270"},
        {1, "48e698368db95cfbf6fbb47254c7c0f8",
            "08351a09ee26c553e9b883ad73c9d811"},
        {5, "acd447a518416b43da012d55620077c1",
            "b91e712e3e188fcb90349c1b82942fd1"},
    };
    for (const auto& vector : vectors) {
        for (int i = 0; i < 0x1000; i++) // the same input for every sector
            sector[i] = (unsigned char)(i * 7 + 3);
        setup::xts_decrypt_sector(data_key, tweak_key, vector.index, sector);
        unsigned char first[16], last[16];
        for (int i = 0; i < 16; i++) {
            (void)sscanf(vector.first + i * 2, "%2hhx", &first[i]);
            (void)sscanf(vector.last + i * 2, "%2hhx", &last[i]);
        }
        check(same(sector, first, 16), "XTS decrypts the first bytes of a sector");
        check(same(sector + 0x1000 - 16, last, 16), "XTS decrypts the last bytes of a sector");
    }
    if (!failures)
        std::printf("ok\n");
    return failures ? 1 : 0;
}
