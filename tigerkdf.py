#   TigerKDF reference Python implementation
#
#   Written in 2014 by Bill Cox <waywardgeek@gmail.com>
#
#   To the extent possible under law, the author(s) have dedicated all copyright
#   and related and neighboring rights to this software to the public domain
#   worldwide. This software is distributed without any warranty.
#
#   You should have received a copy of the CC0 Public Domain Dedication along with
#   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

from Crypto.Hash.hashalgo import HashAlgo
from pbkdf2 import PBKDF2

# You must build the blake2 package from the latest git master.  The released package does
# not handle 0's in the input causing PBKDF2 to fail, as it pads the input with 0's.
#     https://github.com/darjeeling/python-blake2
#
# From the command line, go to the python-blake2 directory and issue:
#  > python2 setup.py build
#  > sudo python2 setup.py install
import blake2

import os

BLAKE2S_OUTBYTES=32
TIGERKDF_SLICES=16

# A simple digest class wrapper for Blake2

class Blake2Hash:

    blockSize = 1        # legacy value (wrong in any useful sense)
    digest_size = 32
    digestsize = 32

    def __init__(self, data=""):
        if data == None:
            data = ""
        #print "blake2s: init", toHex(data)
        self.data = data

    def digest(self):
        result = blake2.blake2s(self.data, 32, "", rawOutput=False)
        #print "blake2s: digest result", toHex(self.data), "result", toHex(result)
        return result

    def update(self, data):
        if data == None:
            data = ""
        #print "blake2s: update", toHex(data)
        self.data += data

    def hexdigest(self):
        result = blake2.blake2s(self.data, 32, "", rawOutput=False)
        #print "blake2s: hexdigest input", toHex(self.data), "result", toHex(result)
        return toHex(result)

    def copy(self):
        return Blake2Hash(self.data)

    @staticmethod
    def new():
        return Blake2Hash()

def toHex(s):
    return "".join("{0:02X}".format(ord(c)) for c in str(s))

def toUint32Array(b):
    words = []
    for i in range(0, len(b), 4):
        v = b[i]
        v = (v << 8) | b[i+1]
        v = (v << 8) | b[i+2]
        v = (v << 8) | b[i+3]
        words.append(v)
    return words

def toUint8Array(words):
    b = bytearray()
    for i in range(len(words)):
        word = words[i]
        b3 = word & 0xff
        word >>= 8
        b2 = word & 0xff
        word >>= 8
        b1 = word & 0xff
        word >>= 8
        b0 = word & 0xff
        b.append(b0)
        b.append(b1)
        b.append(b2)
        b.append(b3)
    return b

def H(outlen, data, key=""):
    data = str(data)
    key = str(key)
    return bytearray(blake2.blake2s(data, outlen, key, rawOutput=False))

def H_PBKDF2(hashSize, password, salt):
    """This is a PBKDF2 password hashing function based currently on Blake2s."""
    salt = str(salt)
    password = str(password)
    return bytearray(PBKDF2(password, salt, iterations=1, digestmodule=Blake2Hash).read(hashSize))

def TigerKDF_HashPassword(hashSize, password, salt, data, startMemCost, stopMemCost, timeCost,
        blockSize, subBlockSize, parallelism):
    """The full password hashing interface."""
    if data != None:
        derivedSalt = H_PBKDF2(hashSize, data, salt)
        hash = H_PBKDF2(hashSize, password, derivedSalt)
    else:
        hash = H_PBKDF2(hashSize, password, salt)
    return TigerKDF(hash, startMemCost, stopMemCost, timeCost, blockSize/4, subBlockSize/4, parallelism, False)

def hashWithSalt(state, salt):
    """Perform one crypto-strength hash on a 32-byte state, with a 32-bit salt."""
    buf = toUint8Array(state)
    s = toUint8Array([salt])
    buf = H(32, buf, s)
    buf = toUint32Array(buf)
    for i in range(8):
        state[i] = buf[i]

def hashTo256(hash):
    """Hash a variable length hash to a 256-bit hash."""
    buf = H(32, hash)
    return toUint32Array(buf)

def addIntoHash(hash256, mem, parallelism, blocklen, blocksPerThread):
    """Add the last hashed data into the result."""
    for p in range(parallelism):
        for i in range(8):
            hash256[i] += mem[(p+1)*blocklen*blocksPerThread + i - 8]

def reverse(v, numBits):
    """Compute the bit reversal of v."""
    result = 0
    while numBits != 0:
        numBits -= 1
        result = (result << 1) | (v & 1)
        v >>= 1
    return result

def hashBlocks(state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions):
    """Hash three blocks together with fast SSE friendly hash function optimized for high memory bandwidth."""

    # Do SIMD friendly memory hashing and a scalar CPU friendly parallel multiplication chain
    numSubBlocks = blocklen/subBlocklen
    oddState = list(state)
    for i in range(8):
        oddState[i] |= 1
    v = 1

    for r in range(repetitions):
        for i in range(numSubBlocks):
            randVal = mem[fromAddr]
            p = prevAddr + subBlocklen*(randVal & (numSubBlocks - 1))
            for j in range(subBlocklen/8):

                # Compute the multiplication chain
                for k in range(multiplies):
                    v = (0xffffffff & v) * oddState[k]
                    v ^= randVal
                    randVal += v >> 32;

                # Hash 32 bytes of memory
                for k in range(8):
                    state[k] = (state[k] + mem[p]) ^ mem[fromAddr]
                    state[k] = 0xffffffff & ((state[k] >> 24) | (state[k] << 8))
                    mem[toAddr] = state[k]
                    p += 1
                    fromAddr += 1
                    toAddr += 1
    hashWithSalt(state, v)

def hashWithoutPassword(state, mem, p, blocklen, blocksPerThread, multiplies, repetitions, parallelism, completedBlocks):
    """Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
       Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal."""

    start = blocklen*blocksPerThread*p
    firstBlock = completedBlocks
    if completedBlocks == 0:
        # Initialize the first block of memory
        for i in range(blocklen/8):
            buf = list(state)
            hashWithSalt(buf, i)
            for j in range(8):
                mem[start + 8*i + j] = buf[j]
        firstBlock = 1

    # Hash one "slice" worth of memory hashing
    numBits = 1; # The number of bits in i
    for i in range(firstBlock, completedBlocks + blocksPerThread/TIGERKDF_SLICES):
        while 1 << numBits <= i:
            numBits += 1

        # Compute the "sliding reverse" block position
        reversePos = reverse(i, numBits-1)
        if reversePos + (1 << (numBits-1)) < i:
            reversePos += 1 << (numBits-1)
        fromAddr = blocklen*reversePos # Start for fromAddr is computed in hashBlocks

        # Compute which thread's memory to read from
        if fromAddr < completedBlocks*blocklen:
            fromAddr += blocklen*blocksPerThread*(i % parallelism)
        else:
            fromAddr += start

        toAddr = start + i*blocklen
        prevAddr = toAddr - blocklen
        hashBlocks(state, mem, blocklen, blocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions)

def hashWithPassword(state, mem, p, blocklen, subBlocklen, blocksPerThread, multiplies,
        repetitions, parallelism, completedBlocks):
    """Hash memory with password dependent addressing."""

    start = blocklen*blocksPerThread*p

    # Hash one "slice" worth of memory hashing
    for i in range(completedBlocks, completedBlocks + blocksPerThread/TIGERKDF_SLICES):

        # Compute rand()^3 distance distribution
        v = state[0]
        v2 = v*v >> 32
        v3 = v*v2 >> 32
        distance = (i-1)*v3 >> 32

        # Hash the prior block and the block at 'distance' blocks in the past
        fromAddr = (i - 1 - distance)*blocklen

        # Compute which thread's memory to read from
        if fromAddr < completedBlocks*blocklen:
            fromAddr += blocklen*(state[1] % parallelism)*blocksPerThread
        else:
            fromAddr += start

        toAddr = start + i*blocklen
        prevAddr = toAddr - blocklen
        hashBlocks(state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions)

def hashMemory(hash, mem, blocksPerThread, blocklen, subBlocklen, multiplies, parallelism, repetitions):
    """Hash memory for one level of garlic."""

    # Convert hash to 8 32-bit ints.
    hash256 = hashTo256(hash)

    # Initialize thread states
    states = [list(hash256) for _ in range(parallelism)]
    for p in range(parallelism):
        hashWithSalt(states[p], p)

    # Do the the first "resistant" loop in "slices"
    for slice in range(TIGERKDF_SLICES/2):
        for p in range(parallelism):
            hashWithoutPassword(states[p], mem, p, blocklen, blocksPerThread, multiplies, repetitions,
                parallelism, slice*blocksPerThread/TIGERKDF_SLICES)

    # Do the second "unpredictable" loop in "slices"
    for slice in range(TIGERKDF_SLICES/2, TIGERKDF_SLICES):
        for p in range(parallelism):
            hashWithPassword(states[p], mem, p, blocklen, subBlocklen, blocksPerThread, multiplies,
                repetitions, parallelism, slice*blocksPerThread/TIGERKDF_SLICES)

    # Apply a crypto-strength hash
    addIntoHash(hash256, mem, parallelism, blocklen, blocksPerThread)
    hash = H_PBKDF2(len(hash), toUint8Array(hash256), "")

def TigerKDF(hash, startMemCost, stopMemCost, timeCost, blocklen, subBlocklen, parallelism, updateMemCostMode):
    """The TigerKDF password hashing function."""

    # Allocate memory
    blocksPerThread = TIGERKDF_SLICES*((1 << stopMemCost)/(TIGERKDF_SLICES*parallelism))
    mem = [0 for _ in range(blocklen*blocksPerThread*parallelism)]

    # Expand time cost into multiplies and repetitions
    if(timeCost <= 8):
        multiplies = timeCost
        repetitions = 1
    else:
        multiplies = 8
        repetitions = 1 << (timeCost - 8)

    # Iterate through the levels of garlic.  Throw away some early memory to reduce the
    # danger from leaking memory to an attacker.
    for i in range(stopMemCost+1):
        if i >= startMemCost or (not updateMemCostMode and i < startMemCost - 6):
            blocksPerThread = TIGERKDF_SLICES*((1 << i)/(TIGERKDF_SLICES*parallelism))
            if blocksPerThread >= TIGERKDF_SLICES:
                hashMemory(hash, mem, blocksPerThread, blocklen, subBlocklen, multiplies, parallelism, repetitions)

import pdb; pdb.set_trace()
hash = TigerKDF_HashPassword(32, "password", "salt", None, 12, 12, 1, 256, 64, 2)
print toHex(str(hash))
