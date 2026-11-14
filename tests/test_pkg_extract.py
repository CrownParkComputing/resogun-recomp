"""scripts/pkg_extract.py without a .pkg: the AES, the package header and the PFS it reads."""
import struct
import tempfile
import unittest
from pathlib import Path

from paths import ROOT  # noqa: F401  (sys.path for scripts/)
import pkg_extract


def aes_vector():
    """FIPS-197, appendix C.1: the first AES-128 vector."""
    key = bytes(range(16))
    plain = bytes.fromhex('00112233445566778899aabbccddeeff')
    return key, plain, bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')


class AesTests(unittest.TestCase):
    def test_aes_encrypts_the_fips_197_vector(self):
        key, plain, expected = aes_vector()
        self.assertEqual(pkg_extract.Aes128(key).encrypt_block(plain), expected)

    def test_aes_decrypts_the_fips_197_vector(self):
        key, plain, expected = aes_vector()
        self.assertEqual(pkg_extract.Aes128(key).decrypt_block(expected), plain)

    def test_aes_rejects_a_key_of_the_wrong_size(self):
        with self.assertRaises(pkg_extract.PkgError):
            pkg_extract.Aes128(b'short')

    def test_aes_cbc_chains_the_blocks(self):
        key, plain, _ = aes_vector()
        cipher = pkg_extract.Aes128(key)
        iv = bytes(range(16, 32))
        # The CBC encryption of two blocks, done here: the extractor only ever decrypts.
        first = cipher.encrypt_block(bytes(a ^ b for a, b in zip(plain, iv)))
        second = cipher.encrypt_block(bytes(a ^ b for a, b in zip(plain, first)))
        self.assertEqual(cipher.decrypt_cbc(first + second, iv), plain + plain)


class PkgTests(unittest.TestCase):
    """A package header and its table, as the extractor reads them."""
    def package(self, entries=(), names=b''):
        data = bytearray(0x4000)
        struct.pack_into('>I', data, 0, 0x7F434E54)  # the magic
        struct.pack_into('>I', data, 0x0C, 1)  # the file count
        struct.pack_into('>I', data, 0x10, len(entries))
        struct.pack_into('>I', data, 0x18, 0x200)  # the table
        struct.pack_into('>Q', data, 0x410, 0x400)  # the PFS image
        struct.pack_into('>Q', data, 0x418, 0x100)
        for index, entry in enumerate(entries):
            struct.pack_into('>6I', data, 0x200 + index * 32, *entry)
        data[0x3200:0x3200 + len(names)] = names  # the table of names
        return bytes(data), names

    def test_a_file_that_is_not_a_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'x.pkg'
            path.write_bytes(b'\0' * 0x1000)
            with self.assertRaisesRegex(pkg_extract.PkgError, 'not a PS4 .pkg'):
                pkg_extract.Pkg(path)

    def test_a_file_that_is_too_small_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'x.pkg'
            path.write_bytes(b'\x7fCNT')
            with self.assertRaisesRegex(pkg_extract.PkgError, 'too small'):
                pkg_extract.Pkg(path)

    def test_the_header_and_the_table_are_read(self):
        entries = [(0x1000, 1, 0, 0, 0xE3B0, 1656), (0x20, 0, 0xE0000000, 0x3000, 0x2800, 256)]
        data, _ = self.package(entries)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'x.pkg'
            path.write_bytes(data)
            package = pkg_extract.Pkg(path)
            self.assertEqual(package.pfs_offset, 0x400)
            self.assertEqual(package.pfs_size, 0x100)
            self.assertEqual(len(package.entries[0x1000]), 1)
            self.assertEqual(package.entries[0x20][0]['offset'], 0x2800)
            self.assertEqual(package.entries[0x20][0]['key_index'], 3)
            self.assertTrue(package.entries[0x20][0]['flags'] & 0x80000000)

    def test_the_named_entries_are_the_ones_with_a_name(self):
        names = b'\0param.sfo\0icon0.png\0'
        entries = [(0x1000, 1, 0, 0, 0xE3B0, 8), (0x100B, 11, 0, 0, 0xEA30, 4),
                   (0x200, 0, 0, 0, 0x3200, len(names))]
        data, _ = self.package(entries, names)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'x.pkg'
            path.write_bytes(data)
            package = pkg_extract.Pkg(path)
            found = {name: entry['offset'] for name, entry in package.named_entries()}
            self.assertEqual(found, {b'param.sfo': 0xE3B0, b'icon0.png': 0xEA30})


class PfsTests(unittest.TestCase):
    """A PFS image: the header, the inodes and the directories."""
    def image(self, inodes=(), directories=()):
        """A PFS image with a header, an inode table and one directory."""
        block_size = 0x10000
        header = bytearray(0x380)
        struct.pack_into('<Q', header, 0, 1)  # the version
        struct.pack_into('<Q', header, 8, 20130315)  # the format
        struct.pack_into('<H', header, 0x1C, 8)  # the mode: not signed, not encrypted
        struct.pack_into('<I', header, 0x20, block_size)
        struct.pack_into('<Q', header, 0x28, 2)  # the blocks
        struct.pack_into('<Q', header, 0x30, len(inodes))
        struct.pack_into('<Q', header, 0x38, 2)
        struct.pack_into('<Q', header, 0x40, 1)  # the inode blocks
        struct.pack_into('<Q', header, 0x48, 0)  # the superroot
        table = bytearray()
        for inode in inodes:
            raw = bytearray(168)
            struct.pack_into('<H', raw, 0, inode['mode'])
            struct.pack_into('<I', raw, 4, 0)
            struct.pack_into('<Q', raw, 8, inode['size'])
            struct.pack_into('<I', raw, 0x60, inode['blocks'])
            for index, block in enumerate(inode['direct']):
                struct.pack_into('<I', raw, 0x64 + index * 4, block)
            table += raw
        image = bytearray(header) + bytearray(block_size - len(header)) + table
        image += bytearray(block_size - len(table))
        for directory in directories:
            block = bytearray(block_size)
            block[:len(directory['data'])] = directory['data']
            image[block_size * directory['block']:block_size * (directory['block'] + 1)] = block
        return bytes(image)

    def dirent(self, number, kind, name):
        """A directory entry: its header and its name."""
        raw = bytearray(16)
        struct.pack_into('<4I', raw, 0, number, kind, len(name), 16 + len(name) + 1)
        return bytes(raw) + name + b'\0'

    def test_the_header_is_read(self):
        image = self.image([{'mode': 0x416D, 'size': 65536, 'blocks': 1, 'direct': [1]}])
        pfs = pkg_extract.Pfs(pkg_extract.BytesImage(image))
        self.assertEqual(pfs.block_size, 0x10000)
        self.assertEqual(pfs.inode_count, 1)
        self.assertEqual(pfs.superroot, 0)
        self.assertFalse(pfs.signed)

    def test_an_image_that_is_not_a_pfs_is_rejected(self):
        with self.assertRaisesRegex(pkg_extract.PkgError, 'not a PFS image'):
            pkg_extract.Pfs(pkg_extract.BytesImage(bytes(0x380)))

    def test_a_directory_lists_its_entries(self):
        entries = self.dirent(1, 2, b'flat_path_table') + self.dirent(2, 3, b'uroot')
        image = self.image(
            [{'mode': 0x416D, 'size': 65536, 'blocks': 1, 'direct': [2]}],
            [{'block': 2, 'data': entries}])
        pfs = pkg_extract.Pfs(pkg_extract.BytesImage(image))
        self.assertEqual(pfs.directory(pfs.inodes[0]),
                         [(b'flat_path_table', 1, 2), (b'uroot', 2, 3)])
        self.assertEqual(pfs.find(pfs.inodes[0], b'uroot'), 2)
        self.assertIsNone(pfs.find(pfs.inodes[0], b'nothing'))

    def test_the_root_is_the_uroot_of_the_superroot(self):
        # The superroot (inode 0) names the flat path table and uroot; uroot is the root.
        entries = self.dirent(1, 2, b'flat_path_table') + self.dirent(2, 3, b'uroot')
        image = self.image(
            [{'mode': 0x416D, 'size': 65536, 'blocks': 1, 'direct': [2]},
             {'mode': 0x8000, 'size': 0, 'blocks': 0, 'direct': []},
             {'mode': 0x416D, 'size': 65536, 'blocks': 1, 'direct': [3]}],
            [{'block': 2, 'data': entries}])
        pfs = pkg_extract.Pfs(pkg_extract.BytesImage(image))
        self.assertIs(pfs.root(), pfs.inodes[2])

    def test_the_root_is_the_superroot_when_there_is_no_uroot(self):
        image = self.image(
            [{'mode': 0x416D, 'size': 65536, 'blocks': 1, 'direct': [2]}],
            [{'block': 2, 'data': self.dirent(1, 2, b'flat_path_table')}])
        pfs = pkg_extract.Pfs(pkg_extract.BytesImage(image))
        self.assertIs(pfs.root(), pfs.inodes[0])


if __name__ == '__main__':
    unittest.main()
