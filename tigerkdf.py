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
    return "".join("{0:02X}".format(ord(c)) for c in s)

def toUint32Array(bytes):
    b = bytearray(bytes)
    words = []
    for i in range(0, len(b), 4):
        value = b[i]
        value = (value << 8) | b[i+1]
        value = (value << 8) | b[i+2]
        value = (value << 8) | b[i+3]
        words.append(value)
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
    return blake2.blake2s(data, outlen, key, rawOutput=False)

def H_PBKDF2(hashSize, password, salt):
    """This is a PBKDF2 password hashing function based currently on Blake2s."""
    salt = str(salt)
    password = str(password)
    return PBKDF2(password, salt, iterations=1, digestmodule=Blake2Hash).read(hashSize)

def TigerKDF_SimpleHashPassword(hashSize, password, salt, memSize):
    hash = H_PBKDF2(hashSize, password, salt)
    return TigerKDF(hash, memSize, 250, 0, 0, 16384, 0, 2, 1, False)

def TigerKDF_HashPassword(hashSize, password, salt, memSize, multipliesPerKB, garlic, data, blockSize,
        subblockSize, parallelism, repetitions):
    """The full password hashing interface.  memSize is in KiB."""
    if data != None:
        derivedSalt = H_PBKDF2(hashSize, data, salt)
        hash = H_PBKDF2(hashSize, password, derivedSalt)
    else:
        hash = H_PBKDF2(hashSize, password, salt)
    return TigerKDF(hash, memSize, multipliesPerKB, 0, garlic, blockSize, subblockSize, parallelism, repetitions, False)

def TigerKDF_UpdatePasswordHash(hash, memSize, multipliesPerKB, oldGarlic, newGarlic,
        blockSize, subblockSize, parallelism, repetitions):
    """Update an existing password hash to a more difficult level of garlic."""
    return TigerKDF(hash, memSize, multipliesPerKB, oldGarlic, newGarlic, blockSize, subblockSize, parallelism,
            repetitions, False)

def TigerKDF_ClientHashPassword(hash, password, salt, memSize, multipliesPerKB, garlic, data, blockSize, subblockSize,
        parallelism, repetitions):
    """Client-side portion of work for server-relief mode."""
    if data != None:
        derivedSalt = H_PBKDF2(hashSize, data, salt)
        hash = H_PBKDF2(hashSize, password, derivedSalt)
    else:
        hash = H_PBKDF2(hashSize, password, salt)
    return TigerKDF(hash, memSize, multipliesPerKB, 0, garlic, blockSize, subblockSize,
            parallelism, repetitions, True)

def TigerKDF_ServerHashPassword(hash):
    """Server portion of work for server-relief mode."""
    H_PBKDF2(len(hash), hash, "");

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

def multHash(hash, numblocks, repetitions, multipliesPerBlock, parallelism):
    """Do low memory-bandwidth multiplication hashing."""
    multHashes = []
    state = list(hash)
    hashWithSalt(state, parallelism)
    for i in range(numblocks*2):
        for j in range(multipliesPerBlock * repetitions):
            # This is reversible, and will not lose entropy
            state[j&7] = (0xffffffff & (state[j&7]*(state[(j+1)&7] | 1))) ^ (state[(j+2)&7] >> 1)
        # Apply a crypto-strength hash to the state and broadcast the result
        hashWithSalt(state, i);
        multHashes.append(list(state))
    return multHashes

def combineHashes(hashSize, mem, blocklen, numblocks, parallelism):
    """Add the last hashed data from each memory thread into the result."""
    hashlen = hashSize/4
    s = [0 for _ in range(hashlen)]
    for p in range(parallelism):
        pos = 2*(p+1)*numblocks*blocklen - hashlen
        for i in range(hashlen):
            s[i] = 0xffffffff & (s[i] + mem[pos + i])
    return toUint8Array(s)

def hashMultIntoState(iteration, multHashes, state):
    """Hash the multiply chain state into our state.  If the multiplies are falling behind, sleep for a while."""
    hash = multHashes[iteration]
    for i in range(8):
        state[i] = 0xffffffff & (state[i] + hash[i])
    hashWithSalt(state, iteration)

def reverse(value, numBits):
    """Compute the bit reversal of value."""
    result = 0
    while numBits != 0:
        numBits -= 1
        result = (result << 1) | (value & 1)
        value >>= 1
    return result

def hashBlocks(state, mem, blocklen, subBlocklen, fromAddr, toAddr, repetitions):
    """Hash three blocks together with fast SSE friendly hash function optimized for high memory bandwidth."""
    prevAddr = toAddr - blocklen
    numSubBlocks = blocklen/subBlocklen
    mask = numSubBlocks - 1
    for r in range(repetitions):
        f = fromAddr
        t = toAddr
        for i in range(numSubBlocks):
            p = prevAddr + subBlocklen*(mem[f] & mask)
            for j in range(subBlocklen/8):
                for k in range(8):
                    state[k] = (0xffffffff & (state[k] + mem[p])) ^ mem[f]
                    state[k] = (state[k] >> 24) | (0xffffffff & (state[k] << 8))
                    mem[t] = state[k]
                    p += 1
                    f += 1
                    t += 1

def hashWithoutPassword(mem, hash, p, blocklen, numblocks, repetitions, multHashes):
    """Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
       Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal."""
    start = 2*p*numblocks*blocklen
    for i in range(blocklen):
        mem[start + i] = 0x5c5c5c5c
    buf = list(hash)
    hashWithSalt(buf, p)
    for i in range(8):
        mem[start + i] = buf[i]
    state = [0, 0, 0, 0, 0, 0, 0, 0]
    hashMultIntoState(0, multHashes, state)
    numBits = 0
    toAddr = start + blocklen
    for i in range(1, numblocks):
        if 1 << (numBits + 1) <= i:
            numBits += 1
        reversePos = reverse(i, numBits)
        if reversePos + (1 << numBits) < i:
            reversePos += 1 << numBits
        fromAddr = start + blocklen*reversePos
        hashBlocks(state, mem, blocklen, blocklen, fromAddr, toAddr, repetitions)
        hashMultIntoState(i, multHashes, state)
        toAddr += blocklen

def hashWithPassword(mem, parallelism, p, blocklen, subBlocklen, numblocks, repetitions, multHashes):
    """Hash memory with dependent memory addressing to thwart TMTO attacks."""
    start = (2*p + 1)*numblocks*blocklen
    state = [1 for _ in range(8)]
    toAddr = start
    for i in range(numblocks):
        v = state[0]
        v2 = v*v >> 32
        v3 = v*v2 >> 32
        distance = (i + numblocks - 1)*v3 >> 32
        if distance < i:
            fromAddr = start + (i - 1 - distance)*blocklen
        else:
            q = (p + i) % parallelism
            b = numblocks - 1 - (distance - i)
            fromAddr = (2*numblocks*q + b)*blocklen
        hashBlocks(state, mem, blocklen, subBlocklen, fromAddr, toAddr, repetitions)
        hashMultIntoState(i + numblocks, multHashes, state)
        toAddr += blocklen

def TigerKDF(hash, memSize, multipliesPerKB, startGarlic, stopGarlic, blockSize, subBlockSize, parallelism,
        repetitions, skipLastHash):
    """The TigerKDF password hashing function.  MemSize is in KiB."""
    # Compute sizes
    memlen = (1 << 10)*memSize/4
    blocklen = blockSize/4
    numblocks = (memlen/(2*parallelism*blocklen)) << startGarlic
    if subBlockSize != 0:
        subBlocklen = subBlockSize/4
    else:
        subBlocklen = blocklen
    memlen = (2*parallelism*numblocks*blocklen) << (stopGarlic - startGarlic)
    multipliesPerBlock = 8*(multipliesPerKB*blockSize/(8*1024))
    if multipliesPerBlock == 0:
        multipliesPerBlock = 8
    # Allocate memory
    mem = [0 for _ in range(memlen)]
    # Iterate through the levels of garlic
    for i in range(startGarlic, stopGarlic+1):
        # Convert hash to 8 32-bit ints
        hash256 = hashTo256(hash)
        # Do the multiplication chains
        multHashes = multHash(hash256, numblocks, repetitions, multipliesPerBlock, parallelism)
        # Do the the first "pure" loop
        for p in range(parallelism):
            hashWithoutPassword(mem, hash256, p, blocklen, numblocks, repetitions, multHashes)
        # Do the second "dirty" loop
        for p in range(parallelism):
            hashWithPassword(mem, parallelism, p, blocklen, subBlocklen, numblocks, repetitions, multHashes)
        # Combine all the memory thread hashes with a crypto-strength hash
        hash = combineHashes(len(hash), mem, blocklen, numblocks, parallelism)
        # Double the memory for the next round of garlic
        numblocks *= 2
        if i < stopGarlic or not skipLastHash:
            # For server relief mode, skip doing this last hash
            hash = H_PBKDF2(len(hash), hash, "")
    # The light is green, the trap is clean
    return hash

#import pdb; pdb.set_trace()
#hash = TigerKDF_SimpleHashPassword(32, "password", "salt", 64)
hash = TigerKDF_HashPassword(32, "password", "salt", 64, 20, 0, None, 1024, 0, 2, 4)
print toHex(str(hash))
