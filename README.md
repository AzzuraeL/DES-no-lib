# DES Encrypted Chat Application

A peer-to-peer encrypted chat application implemented in Python. Messages are encrypted using the **DES (Data Encryption Standard)** block cipher operating in **CBC (Cipher Block Chaining)** mode with **PKCS5 padding**. The DES implementation is written from scratch in pure Python, referencing the open-source [pydes](https://github.com/RobinDavid/pydes) project by Robin David.

---

## Table of Contents

- [Overview](#overview)
- [How to Run](#how-to-run)
- [File Structure](#file-structure)
- [des.py — Detailed Explanation](#despy--detailed-explanation)
  - [Module Docstring and Imports](#module-docstring-and-imports)
  - [DES Constant Tables](#des-constant-tables)
    - [PI — Initial Permutation](#pi--initial-permutation)
    - [CP_1 — Permuted Choice 1 (Key)](#cp_1--permuted-choice-1-key)
    - [CP_2 — Permuted Choice 2 (Key)](#cp_2--permuted-choice-2-key)
    - [E — Expansion Permutation](#e--expansion-permutation)
    - [S_BOX — Substitution Boxes](#s_box--substitution-boxes)
    - [P — P-Box Permutation](#p--p-box-permutation)
    - [PI_1 — Final (Inverse) Permutation](#pi_1--final-inverse-permutation)
    - [SHIFT — Key Schedule Rotation Counts](#shift--key-schedule-rotation-counts)
  - [Utility Functions](#utility-functions)
    - [bytes_to_bit_array()](#bytes_to_bit_arraydata)
    - [bit_array_to_bytes()](#bit_array_to_bytesbits)
    - [nsplit()](#nsplitdata-n)
    - [binvalue()](#binvalueval-bitsize)
  - [The `des` Class](#the-des-class)
    - [Constructor: `__init__()`](#constructor-__init__)
    - [permut()](#permutblock-table)
    - [expand()](#expandblock-table)
    - [xor()](#xort1-t2)
    - [shift()](#shiftg-d-n)
    - [generatekeys()](#generatekeys)
    - [substitute()](#substituted_e)
    - [process_block()](#process_blockblock8-actionencrypt)
  - [Padding Functions](#padding-functions)
    - [addPadding()](#addpaddingdata)
    - [removePadding()](#removepaddingdata)
  - [CBC Mode Functions](#cbc-mode-functions)
    - [encrypt()](#encryptplaintext-key8)
    - [decrypt()](#decryptblob-key8)
- [chat.py — Detailed Explanation](#chatpy--detailed-explanation)
  - [Module Docstring](#module-docstring)
  - [Imports](#imports)
  - [recv_exact()](#recv_exactsock-n)
  - [send_msg()](#send_msgsock-text-key)
  - [receiver_loop()](#receiver_loopsock-key-peer)
  - [main()](#main)
  - [Entry Point Guard](#entry-point-guard)
- [DES Algorithm Walkthrough](#des-algorithm-walkthrough)
  - [Encryption Flow Diagram](#encryption-flow-diagram)
  - [Key Schedule Diagram](#key-schedule-diagram)
  - [CBC Mode Diagram](#cbc-mode-diagram)
- [Security Notice](#security-notice)
- [References](#references)

---

## Overview

This project consists of two Python files:

| File | Purpose |
|------|---------|
| `des.py` | Pure-Python DES implementation (single-block + CBC mode) |
| `chat.py` | TCP peer-to-peer chat that uses `des.py` for encryption |

The chat works by having one party **listen** on a TCP port and the other **connect** to it. Every message typed by either party is encrypted with DES-CBC before being sent over the network, and decrypted upon receipt.

---

## How to Run

### Prerequisites

- Python 3.6 or higher (no external packages required)

### Start the listener (receiver)

```bash
python chat.py listen --port 5000 --key KUNCI123
```

### Connect from another machine (sender)

```bash
python chat.py connect --host <LISTENER_IP> --port 5000 --key KUNCI123
```

### Key format

- **8 ASCII characters**: e.g. `KUNCI123`, `secret_k`
- **16 hex digits** (representing 8 bytes): e.g. `4B554E43493132`+ padding to 16 chars

Both sides **must use the same key** or decryption will fail.

---

## File Structure

```
.
├── README.md    ← This file
├── des.py       ← DES cipher implementation (referenced from pydes)
└── chat.py      ← TCP encrypted chat application
```

---

## des.py — Detailed Explanation

### Module Docstring and Imports

```python
import os
```

The only standard library import is `os`, used exclusively for `os.urandom(8)` to generate a cryptographically secure random **Initialization Vector (IV)** for CBC mode. No third-party libraries are needed because the entire DES algorithm is implemented from scratch.

---

### DES Constant Tables

These tables are defined exactly as specified in the **FIPS 46-3** standard (the official DES specification). They are the heart of the DES algorithm and cannot be changed without breaking compatibility with the standard.

#### PI — Initial Permutation

```python
PI = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4, ...]
```

- **Size**: 64 entries
- **Purpose**: Before any Feistel round begins, the 64-bit plaintext block is permuted (rearranged) according to this table.
- **How it works**: The first bit of the output comes from position 58 of the input, the second bit from position 50, and so on.
- **Why**: The initial permutation was originally designed for hardware implementation efficiency in the 1970s. It has no cryptographic significance by itself, but is part of the standard and must be applied for interoperability.

#### CP_1 — Permuted Choice 1 (Key)

```python
CP_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18, ...]
```

- **Size**: 56 entries (selecting 56 bits from a 64-bit key)
- **Purpose**: The DES key is 64 bits (8 bytes) but only 56 bits are actually used. Every 8th bit is a parity bit that is discarded. CP_1 selects and permutes the 56 effective key bits.
- **How it works**: Bit 57 of the 64-bit key becomes bit 1 of the 56-bit result, bit 49 becomes bit 2, etc.

#### CP_2 — Permuted Choice 2 (Key)

```python
CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4, ...]
```

- **Size**: 48 entries (selecting 48 bits from a 56-bit key)
- **Purpose**: After the two 28-bit key halves are shifted for each round, they are merged back into 56 bits. CP_2 selects 48 of those 56 bits to form the round subkey Ki.
- **Why 48 bits**: The round function needs a 48-bit subkey to XOR with the 48-bit expanded R-half.

#### E — Expansion Permutation

```python
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9, ...]
```

- **Size**: 48 entries (expanding 32 bits to 48 bits)
- **Purpose**: The 32-bit right half (R) of the data needs to be XORed with the 48-bit subkey, so it must first be expanded to 48 bits. Some bits are duplicated (e.g., bit 4 appears in both position 4 and position 7 of the output).
- **Cryptographic role**: The duplication introduces diffusion — a change in one input bit affects multiple S-Box inputs.

#### S_BOX — Substitution Boxes

```python
S_BOX = [
  [[14, 4, 13, 1, ...], [0, 15, 7, 4, ...], [4, 1, 14, 8, ...], [15, 12, 8, 2, ...]],
  ...  # 8 S-Boxes total
]
```

- **Structure**: 8 S-Boxes, each containing 4 rows × 16 columns.
- **Input**: 6 bits → **Output**: 4 bits (per S-Box)
- **How addressing works**:
  - **Row** (2 bits): formed by the 1st and 6th bit of the 6-bit input (range 0–3)
  - **Column** (4 bits): formed by the 2nd through 5th bits (range 0–15)
- **Cryptographic role**: The S-Boxes are the **only non-linear component** of DES. They provide the *confusion* that makes the cipher resistant to linear and algebraic attacks. Without the S-Boxes, DES would be an affine transformation and trivially breakable.

#### P — P-Box Permutation

```python
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10, ...]
```

- **Size**: 32 entries (32-bit → 32-bit)
- **Purpose**: After the S-Box substitution produces 32 bits (8 × 4), the P permutation rearranges them so that in the next round, each S-Box's output bits are spread across multiple different S-Boxes.
- **Cryptographic role**: Provides *diffusion* — ensures that each plaintext bit eventually influences every ciphertext bit (the "avalanche effect").

#### PI_1 — Final (Inverse) Permutation

```python
PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31, ...]
```

- **Size**: 64 entries
- **Purpose**: The exact inverse of the initial permutation PI. Applied after all 16 Feistel rounds to produce the final ciphertext block.
- **Mathematical relationship**: `PI_1[PI[i] - 1] == i + 1` for all i. This means applying PI followed by PI_1 (or vice versa) gives back the original data.

#### SHIFT — Key Schedule Rotation Counts

```python
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
```

- **Size**: 16 entries (one per round)
- **Purpose**: Specifies how many positions to left-circular-shift the two 28-bit key halves before extracting each round's subkey.
- **Total shifts**: 1+1+2+2+2+2+2+2+1+2+2+2+2+2+2+1 = **28**, meaning after all 16 rounds the key halves return to their original position.
- **Pattern**: Rounds 1, 2, 9, and 16 shift by 1; all others shift by 2.

---

### Utility Functions

#### `bytes_to_bit_array(data)`

```python
def bytes_to_bit_array(data):
    array = []
    for byte in data:
        for i in range(7, -1, -1):
            array.append((byte >> i) & 1)
    return array
```

- **Input**: A `bytes` object (e.g., `b"\x41"` = ASCII 'A')
- **Output**: A list of integers, each 0 or 1 (e.g., `[0,1,0,0,0,0,0,1]`)
- **How it works**: For each byte, it iterates from the most significant bit (bit 7) down to the least significant bit (bit 0), extracting each bit using right-shift and bitwise AND.
- **Example**: `bytes_to_bit_array(b"\xCA")` → `[1,1,0,0,1,0,1,0]` (0xCA = 11001010 in binary)

#### `bit_array_to_bytes(bits)`

```python
def bit_array_to_bytes(bits):
    result = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for bit in bits[i:i+8]:
            val = (val << 1) | bit
        result.append(val)
    return bytes(result)
```

- **Input**: A list of bits (0/1 integers), length must be a multiple of 8
- **Output**: A `bytes` object
- **How it works**: Groups bits into chunks of 8, reconstructs each byte by left-shifting and ORing each successive bit.
- **This is the inverse of `bytes_to_bit_array()`**.

#### `nsplit(data, n)`

```python
def nsplit(data, n):
    return [data[k:k+n] for k in range(0, len(data), n)]
```

- **Input**: Any list/sequence `data` and a chunk size `n`
- **Output**: A list of sublists, each of length `n` (the last may be shorter)
- **Used by**: Key schedule (splitting 56-bit key into two 28-bit halves), Feistel rounds (splitting 64-bit block into two 32-bit halves), S-Box processing (splitting 48 bits into eight 6-bit groups)

#### `binvalue(val, bitsize)`

```python
def binvalue(val, bitsize):
    binval = bin(val)[2:]
    if len(binval) > bitsize:
        raise ValueError("binary value larger than the expected size")
    return binval.zfill(bitsize)
```

- **Input**: An integer `val` and a desired `bitsize`
- **Output**: A zero-padded binary string of exactly `bitsize` characters
- **Example**: `binvalue(5, 4)` → `"0101"`
- **Used by**: The `substitute()` method to convert an S-Box output value (0–15) into a 4-bit string.

---

### The `des` Class

The `des` class encapsulates the DES algorithm state (key and subkeys) and provides methods for each step of the cipher.

#### Constructor: `__init__()`

```python
def __init__(self):
    self.password = None
    self.keys = []
```

- `self.password`: Stores the 8-byte key (as `bytes`)
- `self.keys`: Will hold the 16 round subkeys (each a list of 48 bits) after `generatekeys()` is called

#### `permut(block, table)`

```python
def permut(self, block, table):
    return [block[x - 1] for x in table]
```

- **Purpose**: Generic bit permutation. Rearranges the bits of `block` according to `table`.
- **The `-1`**: DES tables use 1-based indexing, but Python lists are 0-based, hence `x - 1`.
- **Used for**: PI (initial permutation), PI_1 (final permutation), CP_1, CP_2, and P.

#### `expand(block, table)`

```python
def expand(self, block, table):
    return [block[x - 1] for x in table]
```

- **Identical to `permut()`** in implementation. It exists as a separate method for code clarity — it signals that the operation is an *expansion* (output is larger than input), not a simple rearrangement.
- **Used for**: The E table (32-bit → 48-bit expansion).

#### `xor(t1, t2)`

```python
def xor(self, t1, t2):
    return [x ^ y for x, y in zip(t1, t2)]
```

- **Purpose**: Element-wise XOR of two bit lists of equal length.
- **Used in**: XORing the expanded R-half with the round subkey, and XORing the result with L.

#### `shift(g, d, n)`

```python
def shift(self, g, d, n):
    return g[n:] + g[:n], d[n:] + d[:n]
```

- **Purpose**: Left circular shift of both 28-bit key halves by `n` positions.
- **How it works**: `g[n:]` gives everything after the first `n` elements; `g[:n]` gives the first `n` elements that "wrap around" to the end.
- **Example**: `shift([1,2,3,4,5], [6,7,8,9,0], 2)` → `([3,4,5,1,2], [8,9,0,6,7])`

#### `generatekeys()`

```python
def generatekeys(self):
    self.keys = []
    key = bytes_to_bit_array(self.password)
    key = self.permut(key, CP_1)
    g, d = nsplit(key, 28)
    for i in range(16):
        g, d = self.shift(g, d, SHIFT[i])
        tmp = g + d
        self.keys.append(self.permut(tmp, CP_2))
```

- **Step-by-step**:
  1. Convert the 8-byte (64-bit) key to a bit array
  2. Apply CP_1 to select and permute the 56 effective key bits
  3. Split into two 28-bit halves: C (g) and D (d)
  4. For each of the 16 rounds:
     - Left-circular-shift both halves by the amount specified in SHIFT
     - Concatenate the shifted halves (56 bits)
     - Apply CP_2 to select 48 bits → this is subkey Ki
  5. Store all 16 subkeys in `self.keys`

#### `substitute(d_e)`

```python
def substitute(self, d_e):
    subblocks = nsplit(d_e, 6)
    result = []
    for i in range(len(subblocks)):
        block = subblocks[i]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOX[i][row][col]
        result += [int(x) for x in binvalue(val, 4)]
    return result
```

- **Input**: A 48-bit list (after XOR with round subkey)
- **Output**: A 32-bit list (after S-Box substitution)
- **Step-by-step**:
  1. Split the 48 bits into 8 groups of 6 bits
  2. For each 6-bit group and corresponding S-Box:
     - **Row**: Combine bit 0 and bit 5 → a 2-bit number (0–3)
     - **Column**: Combine bits 1–4 → a 4-bit number (0–15)
     - **Lookup**: Get the 4-bit value from `S_BOX[i][row][col]`
     - **Convert**: Turn the value into 4 bits and append to result
  3. The result is 8 × 4 = 32 bits

#### `process_block(block8, action=ENCRYPT)`

```python
def process_block(self, block8, action=ENCRYPT):
    block = bytes_to_bit_array(block8)
    block = self.permut(block, PI)
    g, d = nsplit(block, 32)
    for i in range(16):
        d_e = self.expand(d, E)
        if action == ENCRYPT:
            tmp = self.xor(self.keys[i], d_e)
        else:
            tmp = self.xor(self.keys[15 - i], d_e)
        tmp = self.substitute(tmp)
        tmp = self.permut(tmp, P)
        tmp = self.xor(g, tmp)
        g = d
        d = tmp
    final = self.permut(d + g, PI_1)
    return bit_array_to_bytes(final)
```

This is the **core DES algorithm** for a single 64-bit block:

1. **Convert** the 8-byte block to 64 bits
2. **Initial permutation** (PI)
3. **Split** into 32-bit Left (g) and Right (d) halves
4. **16 Feistel rounds**:
   - **Expand** R (d) from 32 bits to 48 bits
   - **XOR** with subkey Ki (for encryption use keys in order; for decryption use keys in reverse)
   - **Substitute** through 8 S-Boxes (48 bits → 32 bits)
   - **Permute** with P (32 bits → 32 bits)
   - **XOR** with L (g)
   - **Swap**: old R becomes new L; result becomes new R
5. **Combine** R + L (note: reversed! This is the "final swap" of the Feistel structure)
6. **Final permutation** (PI_1)
7. **Convert** back to bytes

**Why decryption works with reversed keys**: The Feistel structure has the elegant property that using the same algorithm with subkeys in reverse order perfectly undoes the encryption. No separate decryption algorithm is needed.

---

### Padding Functions

#### `addPadding(data)`

```python
def addPadding(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len]) * pad_len
```

- **Standard**: PKCS5 / PKCS7
- **How it works**: If the data length modulo 8 is `r`, then `8 - r` bytes are appended, each with the value `8 - r`.
- **Example**: `b"Hello"` (5 bytes) → needs 3 bytes of padding → `b"Hello\x03\x03\x03"`
- **Edge case**: If data is already a multiple of 8, a full block of `\x08\x08\x08\x08\x08\x08\x08\x08` is appended. This ensures that padding is always unambiguously removable.

#### `removePadding(data)`

```python
def removePadding(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8 or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding tidak valid (key salah / data rusak)")
    return data[:-pad_len]
```

- **How it works**: Reads the last byte to determine the padding length, validates that all padding bytes have the correct value, then strips them.
- **Error handling**: If the padding is invalid (e.g., because the wrong key was used), a `ValueError` is raised with the message "Padding tidak valid (key salah / data rusak)" ("Invalid padding (wrong key / corrupted data)").

---

### CBC Mode Functions

DES-ECB (Electronic Codebook) encrypts each block independently, which is insecure because identical plaintext blocks produce identical ciphertext blocks. **CBC (Cipher Block Chaining)** fixes this by XORing each plaintext block with the previous ciphertext block before encryption.

#### `encrypt(plaintext, key8)`

```python
def encrypt(plaintext: bytes, key8: bytes) -> bytes:
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
```

- **Step-by-step**:
  1. Create a `des` instance and generate subkeys
  2. Generate a random 8-byte IV using `os.urandom()`
  3. Pad the plaintext with PKCS5
  4. For each 8-byte block:
     - XOR the plaintext block with the previous ciphertext block (or IV for the first block)
     - Encrypt the XORed block with DES
     - The result becomes the `prev` for the next block
  5. Return `IV || ciphertext` (the IV is prepended so the decryptor knows it)

#### `decrypt(blob, key8)`

```python
def decrypt(blob: bytes, key8: bytes) -> bytes:
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
```

- **Step-by-step**:
  1. Extract the first 8 bytes as the IV; the rest is the ciphertext
  2. Validate that the ciphertext length is a non-zero multiple of 8
  3. For each 8-byte ciphertext block:
     - Decrypt the block with DES
     - XOR the result with the previous ciphertext block (or IV for the first)
     - This recovers the original plaintext block
  4. Remove PKCS5 padding from the reassembled plaintext

---

## chat.py — Detailed Explanation

### Module Docstring

```python
"""
(receiver/listener):  python chat.py listen --port 5000 --key KUNCI123
(sender/connector):   python chat.py connect --host <IP_A> --port 5000 --key KUNCI123
"""
```

Quick-reference usage examples right at the top of the file.

### Imports

```python
import argparse, socket, struct, sys, threading
import des
```

| Module | Purpose |
|--------|---------|
| `argparse` | Parses command-line arguments (`mode`, `--host`, `--port`, `--key`) |
| `socket` | TCP networking (creating servers, connecting to peers) |
| `struct` | Packing/unpacking binary data (4-byte message length headers) |
| `sys` | `sys.exit()` for fatal errors |
| `threading` | Running the message receiver in a background thread |
| `des` | Our custom DES module for encryption/decryption |

### `recv_exact(sock, n)`

```python
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup")
        buf += chunk
    return buf
```

- **Purpose**: Reliably receive exactly `n` bytes from a TCP socket.
- **Why it's needed**: TCP is a *stream* protocol. A single `sock.recv(n)` may return fewer than `n` bytes (e.g., due to network fragmentation or OS buffering). This function loops until all `n` bytes have been collected.
- **Error handling**: If `sock.recv()` returns an empty bytes object, the connection has been closed by the peer, so a `ConnectionError` is raised.

### `send_msg(sock, text, key)`

```python
def send_msg(sock, text, key):
    blob = des.encrypt(text.encode("utf-8"), key)
    print(f"   [SEND] plaintext : {text}")
    print(f"   [SEND] ciphertext: {blob[8:].hex().upper()} (IV={blob[:8].hex().upper()})")
    sock.sendall(struct.pack(">I", len(blob)) + blob)
```

- **Step-by-step**:
  1. Encode the text string as UTF-8 bytes
  2. Encrypt using DES-CBC (returns `IV || ciphertext`)
  3. Print debug info showing the plaintext and the ciphertext (hex) with its IV
  4. Send over TCP: first a **4-byte big-endian unsigned integer** containing the blob length, then the blob itself

- **Wire format**: `[4 bytes: length][8 bytes: IV][N bytes: ciphertext]`
- **`struct.pack(">I", len(blob))`**: The `>` means big-endian byte order; `I` means unsigned 32-bit integer. This gives us a length header so the receiver knows exactly how many bytes to read.

### `receiver_loop(sock, key, peer)`

```python
def receiver_loop(sock, key, peer):
    try:
        while True:
            (n,) = struct.unpack(">I", recv_exact(sock, 4))
            blob = recv_exact(sock, n)
            print(f"\n   [RECV] ciphertext: {blob[8:].hex().upper()} (IV={blob[:8].hex().upper()})")
            try:
                print(f"   [RECV] plaintext : {des.decrypt(blob, key).decode('utf-8')}   (dari {peer})")
            except Exception as e:
                print(f"   [RECV] gagal dekripsi: {e}")
            print("> ", end="", flush=True)
    except (ConnectionError, OSError):
        print("\n[!] Lawan bicara terputus.")
        try: sock.close()
        except OSError: pass
        import os; os._exit(0)
```

- **Runs in a background daemon thread** so it can receive messages while the main thread waits for user input.
- **Step-by-step**:
  1. **Read length header**: Read 4 bytes, unpack as big-endian uint32 → `n`
  2. **Read encrypted blob**: Read exactly `n` bytes
  3. **Display ciphertext**: Show the hex representation of the ciphertext and IV
  4. **Decrypt and display**: Attempt to decrypt with DES-CBC and print the plaintext
  5. **Re-display prompt**: Print `"> "` to restore the input prompt
  6. **Loop forever** until the connection drops

- **Error handling**:
  - Decryption failure (wrong key or corrupted data) is caught and printed as "gagal dekripsi" ("decryption failed")
  - Connection loss triggers a clean shutdown via `os._exit(0)` (forceful exit to immediately terminate all threads)

### `main()`

```python
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["listen", "connect"])
    ap.add_argument("--host", default="0.0.0.0", help="IP tujuan (connect) / bind (listen)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", required=True, help="Key DES: 8 karakter ASCII, atau 16 digit hex")
    a = ap.parse_args()
```

**Argument parsing**:

| Argument | Required | Description |
|----------|----------|-------------|
| `mode` | Yes | Either `listen` (act as server) or `connect` (act as client) |
| `--host` | No (default `0.0.0.0`) | IP to bind to (listen) or connect to (connect) |
| `--port` | No (default `5000`) | TCP port number |
| `--key` | Yes | The DES key (8 ASCII chars or 16 hex digits) |

```python
    key = bytes.fromhex(a.key) if len(a.key) == 16 and all(c in "0123456789abcdefABCDEF" for c in a.key) else a.key.encode()
    if len(key) != 8:
        sys.exit("Key harus 8 byte (8 karakter ASCII atau 16 hex).")
```

**Key parsing logic**:
- If the key string is exactly 16 characters and all are valid hexadecimal digits → treat it as a hex-encoded 8-byte key (`bytes.fromhex()`)
- Otherwise → treat it as an ASCII string and encode to bytes (`a.key.encode()`)
- If the result is not exactly 8 bytes, exit with an error

```python
    if a.mode == "listen":
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((a.host, a.port)); srv.listen(1)
        print(f"[*] Menunggu koneksi di {a.host}:{a.port} ...")
        sock, addr = srv.accept()
    else:
        sock = socket.create_connection((a.host, a.port)); addr = (a.host, a.port)
```

**Connection setup**:

- **Listen mode**:
  1. Create a TCP socket
  2. Set `SO_REUSEADDR` to allow quick restart without "Address already in use" errors
  3. Bind to the specified host and port
  4. Listen for one incoming connection
  5. `accept()` blocks until a peer connects, then returns the connection socket and peer address

- **Connect mode**:
  1. `socket.create_connection()` handles DNS resolution and establishes a TCP connection to the specified host and port

```python
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] Tersambung dengan {peer}. Ketik pesan lalu Enter.")
    threading.Thread(target=receiver_loop, args=(sock, key, peer), daemon=True).start()
```

- Format the peer's address as `IP:port`
- Start the `receiver_loop` in a **daemon thread** (daemon threads are automatically killed when the main thread exits)

```python
    try:
        while True:
            line = input("> ")
            if line.strip().lower() == "exit": break
            if line: send_msg(sock, line, key)
    except (EOFError, KeyboardInterrupt):
        pass
    sock.close()
```

**Main input loop**:
- Prompts with `"> "` and waits for user input
- Typing `exit` cleanly disconnects
- Any non-empty line is encrypted and sent
- `Ctrl+C` or `Ctrl+D` also exits gracefully
- The socket is closed on exit

### Entry Point Guard

```python
if __name__ == "__main__":
    main()
```

Standard Python idiom: only run `main()` when the script is executed directly, not when imported as a module.

---

## DES Algorithm Walkthrough

### Encryption Flow Diagram

```
                        64-bit Plaintext Block
                               │
                    ┌──────────▼──────────┐
                    │  Initial Permutation │  (PI table)
                    │      (64 → 64)       │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Split into L₀, R₀  │  (32 bits each)
                    └──────────┬──────────┘
                               │
              ┌────────────────▼────────────────┐
              │         16 Feistel Rounds         │
              │                                   │
              │  For each round i (0..15):         │
              │                                   │
              │    Expand Rᵢ   (32 → 48 bits)     │
              │        │                          │
              │    XOR with Kᵢ  (48 ⊕ 48)        │
              │        │                          │
              │    S-Box Subst. (48 → 32 bits)    │
              │        │                          │
              │    P Permutation (32 → 32)        │
              │        │                          │
              │    XOR with Lᵢ  (32 ⊕ 32)        │
              │        │                          │
              │    Lᵢ₊₁ = Rᵢ                      │
              │    Rᵢ₊₁ = result                   │
              │                                   │
              └────────────────┬────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Combine R₁₆ + L₁₆   │  (note the swap!)
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Final Permutation   │  (PI_1 table)
                    │     (64 → 64)        │
                    └──────────┬──────────┘
                               │
                        64-bit Ciphertext Block
```

### Key Schedule Diagram

```
                         64-bit Key
                             │
                  ┌──────────▼──────────┐
                  │  Permuted Choice 1   │  (CP_1: 64 → 56 bits)
                  │  (drop parity bits)  │
                  └──────────┬──────────┘
                             │
                  ┌──────────▼──────────┐
                  │  Split into C₀, D₀   │  (28 bits each)
                  └──────────┬──────────┘
                             │
                ┌────────────▼────────────┐
                │   For each round i:      │
                │                          │
                │   Left-shift Cᵢ by       │
                │   SHIFT[i] positions     │
                │                          │
                │   Left-shift Dᵢ by       │
                │   SHIFT[i] positions     │
                │                          │
                │   Merge: Cᵢ₊₁ || Dᵢ₊₁   │
                │   (56 bits)              │
                │          │               │
                │   Apply CP_2             │
                │   (56 → 48 bits)         │
                │          │               │
                │   → Round subkey Kᵢ      │
                └────────────┬────────────┘
                             │
                  16 subkeys: K₁, K₂, ..., K₁₆
```

### CBC Mode Diagram

**Encryption:**
```
  IV ─────────┐
              ▼
  P₁ ──► XOR ──► DES_Encrypt ──► C₁ ──────┐
                                            │
              ┌─────────────────────────────┘
              ▼
  P₂ ──► XOR ──► DES_Encrypt ──► C₂ ──────┐
                                            │
              ┌─────────────────────────────┘
              ▼
  P₃ ──► XOR ──► DES_Encrypt ──► C₃
  
  Output: IV || C₁ || C₂ || C₃
```

**Decryption:**
```
  IV ─────────┐
              ▼
  C₁ ──► DES_Decrypt ──► XOR ──► P₁
  │
  └───────────┐
              ▼
  C₂ ──► DES_Decrypt ──► XOR ──► P₂
  │
  └───────────┐
              ▼
  C₃ ──► DES_Decrypt ──► XOR ──► P₃
```

---

## Security Notice

> ⚠️ **DES is NOT secure for production use.** DES has a 56-bit key, which is vulnerable to brute-force attacks. It was officially retired by NIST in 2005. This implementation is for **educational purposes only** — to understand symmetric-key cryptography, Feistel networks, and block cipher modes of operation.
>
> For real-world applications, use **AES-256** (via Python's `cryptography` library or similar).

---

## References

- [FIPS 46-3: Data Encryption Standard (DES)](https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25) — The official DES specification
- [pydes by Robin David](https://github.com/RobinDavid/pydes) — Pure-Python DES reference implementation used as the basis for this code
- [Wikipedia: DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) — General overview of the algorithm
- [Wikipedia: Feistel cipher](https://en.wikipedia.org/wiki/Feistel_cipher) — The structure underlying DES
- [Wikipedia: Block cipher mode of operation (CBC)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC) — How CBC mode works
