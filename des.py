#-*- coding: utf8 -*-
"""
Reference: https://github.com/RobinDavid/pydes
"""

import os

# ============================================================
# DES constant tables (as defined in FIPS 46-3)
# ============================================================

# Initial permutation matrix for the data block (64-bit -> 64-bit)
PI = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Initial permutation applied on the key (64-bit -> 56-bit, dropping parity bits)
CP_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Permutation applied on shifted key halves to produce each round subkey Ki (56-bit -> 48-bit)
CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# Expansion permutation to expand the 32-bit R half to 48 bits for XOR with Ki
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-Boxes: 8 substitution boxes, each mapping 6-bit input to 4-bit output
S_BOX = [

[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Permutation applied after each S-Box substitution in each round (32-bit -> 32-bit)
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Final (inverse initial) permutation for data after the 16 rounds (64-bit -> 64-bit)
PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def bytes_to_bit_array(data):
    """Convert a bytes object into a list of integer bits (0/1)."""
    array = []
    for byte in data:
        for i in range(7, -1, -1):
            array.append((byte >> i) & 1)
    return array

def bit_array_to_bytes(bits):
    """Convert a list of bits back into a bytes object."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for bit in bits[i:i+8]:
            val = (val << 1) | bit
        result.append(val)
    return bytes(result)

def nsplit(data, n):
    """Split a list into sublists of size *n*."""
    return [data[k:k+n] for k in range(0, len(data), n)]

def binvalue(val, bitsize):
    """Return the binary representation of *val* as a string of length *bitsize*."""
    binval = bin(val)[2:]
    if len(binval) > bitsize:
        raise ValueError("binary value larger than the expected size")
    return binval.zfill(bitsize)


ENCRYPT = 1
DECRYPT = 0


class des():
    """
    Pure-Python DES cipher engine.

    Provides low-level single-block encrypt/decrypt as well as
    higher-level CBC-mode helpers used by the chat application.
    """

    def __init__(self):
        self.password = None
        self.keys = []


    def permut(self, block, table):
        """Permute *block* according to the given *table*."""
        return [block[x - 1] for x in table]

    def expand(self, block, table):
        """Expand *block* using the given *table* (same logic as permut)."""
        return [block[x - 1] for x in table]

    def xor(self, t1, t2):
        """Element-wise XOR of two equal-length bit lists."""
        return [x ^ y for x, y in zip(t1, t2)]


    def shift(self, g, d, n):
        """Left-circular-shift both halves *g* and *d* by *n* positions."""
        return g[n:] + g[:n], d[n:] + d[:n]

    def generatekeys(self):
        """Generate all 16 round subkeys from ``self.password``."""
        self.keys = []
        key = bytes_to_bit_array(self.password)
        key = self.permut(key, CP_1)            # Apply the initial permutation on the key
        g, d = nsplit(key, 28)                   # Split into LEFT (g) and RIGHT (d)
        for i in range(16):
            g, d = self.shift(g, d, SHIFT[i])    # Circular shift for this round
            tmp = g + d                          # Merge halves
            self.keys.append(self.permut(tmp, CP_2))  # Compress to 48-bit subkey


    def substitute(self, d_e):
        """Apply the 8 S-Box substitutions on a 48-bit expanded block."""
        subblocks = nsplit(d_e, 6)               # Split into 8 groups of 6 bits
        result = []
        for i in range(len(subblocks)):
            block = subblocks[i]
            row = (block[0] << 1) | block[5]     # Row from first and last bit
            col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
            val = S_BOX[i][row][col]              # Lookup in the appropriate S-Box
            result += [int(x) for x in binvalue(val, 4)]
        return result


    def process_block(self, block8, action=ENCRYPT):
        """
        Encrypt or decrypt a single 8-byte block using DES.

        The 16 round subkeys must already have been generated
        via ``generatekeys()`` before calling this method.
        """
        block = bytes_to_bit_array(block8)
        block = self.permut(block, PI)           # Initial permutation
        g, d = nsplit(block, 32)                 # Split into L and R halves

        for i in range(16):                      # 16 Feistel rounds
            d_e = self.expand(d, E)              # Expand R to 48 bits
            if action == ENCRYPT:
                tmp = self.xor(self.keys[i], d_e)
            else:
                tmp = self.xor(self.keys[15 - i], d_e)
            tmp = self.substitute(tmp)           # S-Box substitution
            tmp = self.permut(tmp, P)            # P permutation
            tmp = self.xor(g, tmp)
            g = d
            d = tmp

        final = self.permut(d + g, PI_1)         # Final permutation (note: d+g swap)
        return bit_array_to_bytes(final)


# ============================================================
# PKCS5 padding
# ============================================================

def addPadding(data):
    """Pad *data* (bytes) to a multiple of 8 bytes using PKCS5."""
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len]) * pad_len

def removePadding(data):
    """Remove PKCS5 padding; raises on invalid padding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8 or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding tidak valid (key salah / data rusak)")
    return data[:-pad_len]

# ============================================================
# CBC-mode encrypt / decrypt  (used by chat.py)
# ============================================================

def encrypt(plaintext: bytes, key8: bytes) -> bytes:
    """
    Encrypt *plaintext* bytes with DES in CBC mode.

    A random 8-byte IV is prepended to the returned ciphertext.
    """
    d = des()
    d.password = key8
    d.generatekeys()

    iv = os.urandom(8)
    prev = iv
    out = b""
    data = addPadding(plaintext)
    for i in range(0, len(data), 8):
        blk = bytes(a ^ b for a, b in zip(data[i:i+8], prev))
        prev = d.process_block(blk, ENCRYPT)
        out += prev
    return iv + out

def decrypt(blob: bytes, key8: bytes) -> bytes:
    """
    Decrypt a CBC-mode DES blob (IV ∥ ciphertext) and strip padding.
    """
    d = des()
    d.password = key8
    d.generatekeys()

    iv, ct = blob[:8], blob[8:]
    if len(ct) == 0 or len(ct) % 8:
        raise ValueError("Panjang ciphertext tidak valid")
    prev = iv
    out = b""
    for i in range(0, len(ct), 8):
        blk = ct[i:i+8]
        decrypted = d.process_block(blk, DECRYPT)
        out += bytes(a ^ b for a, b in zip(decrypted, prev))
        prev = blk
    return removePadding(out)
