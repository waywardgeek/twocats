from pbkdf2 import PBKDF2
from Crypto.Hash import SHA256
import os

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

def H(size, password, salt):
    return PBKDF2(password, salt, iterations=1, digestmodule=SHA256).read(size)

def NoelKDF_SimpleHashPassword(hashsize, password, salt, memsize):
    hash = H(hashsize, password, salt)
    return NoelKDF(hash, memsize, 0, 0, 4096, 1, 1)

def NoelKDF_HashPassword(hashsize, password, salt, memsize, garlic, data, blocksize,
        parallelism, repetitions):
    if data != None:
        derivedSalt = H(hashsize, data, salt)
        hash = H(hashsize, password, derivedSalt)
    else:
        hash = H(hashsize, password, salt)
    return NoelKDF(hash, memsize, 0, garlic, blocksize, parallelism, repetitions)

def NoelKDF_UpdatePasswordHash(hash, memsize, oldGarlic, newGarlic, blocksize, parallelism, repetitions):
    return NoelKDF(hash, memsize, oldGarlic, newGarlic, blocksize, parallelism, repetitions)

def NoelKDF(hash, memsize, startGarlic, stopGarlic, blocksize, parallelism, repetitions):
    memlen = (1 << 20)*memsize/4
    blocklen = blocksize/4
    numblocks = (memlen/(2*parallelism*blocklen)) << startGarlic
    memlen = 2*parallelism*numblocks*blocklen
    mem = [0 for _ in range((1 << (stopGarlic - startGarlic))*memlen)]
    for i in range(startGarlic, stopGarlic+1):
        for p in range(parallelism):
            hashWithoutPassword(p, hash, mem, blocklen, numblocks, repetitions)
        for p in range(parallelism):
            hashWithPassword(p, mem, blocklen, numblocks, parallelism, repetitions)
        hash = xorIntoHash(hash, mem, blocklen, numblocks, parallelism)
        numblocks *= 2
        hash = H(len(hash), hash, str(bytearray([i])))
    return hash

def hashWithoutPassword(p, hash, mem, blocklen, numblocks, repetitions):
    start = 2*p*numblocks*blocklen
    threadKey = toUint32Array(H(blocklen*4, hash, str(toUint8Array([p]))))
    for i in range(blocklen):
        mem[start + i] = threadKey[i]
    value = 1
    mask = 1
    toAddr = start + blocklen
    for i in range(1, numblocks):
        if mask << 1 <= i:
            mask = mask << 1
        reversePos = bitReverse(i, mask)
        if reversePos + mask < i:
            reversePos += mask
        fromAddr = start + blocklen*reversePos
        value = hashBlocks(value, mem, blocklen, fromAddr, toAddr, repetitions)
        toAddr += blocklen

def hashWithPassword(p, mem, blocklen, numblocks, parallelism, repetitions):
    start = (2*p + 1)*numblocks*blocklen
    value = 1
    toAddr = start
    for i in range(numblocks):
        v = value
        v2 = v*v >> 32
        v3 = v*v2 >> 32
        distance = (i + numblocks - 1)*v3 >> 32
        if distance < i:
            fromAddr = start + (i - 1 - distance)*blocklen
        else:
            q = (p + i) % parallelism
            b = numblocks - 1 - (distance - i)
            fromAddr = (2*numblocks*q + b)*blocklen
        value = hashBlocks(value, mem, blocklen, fromAddr, toAddr, repetitions)
        toAddr += blocklen

def hashBlocks(value, mem, blocklen, fromAddr, toAddr, repetitions):
    prevAddr = toAddr - blocklen
    for r in range(repetitions):
        for i in range(blocklen):
            value = (value*(mem[prevAddr + i] | 3) + mem[fromAddr + i]) & 0xffffffff
            mem[toAddr + i] = value
    return value

def xorIntoHash(hash, mem, blocklen, numblocks, parallelism):
    hash = bytearray(hash)
    for p in range(parallelism):
        pos = 2*(p+1)*numblocks*blocklen - len(hash)/4
        data = toUint8Array(mem[pos:pos+len(hash)/4])
        for i in range(len(hash)):
            hash[i] ^= data[i]
    return str(hash)

def bitReverse(value, mask):
    result = 0
    while mask != 1:
        result = (result << 1) | (value & 1)
        value >>= 1
        mask >>= 1
    return result

#import pdb; pdb.set_trace()
#hash = NoelKDF_SimpleHashPassword(32, "password", "salt", 1)
hash = NoelKDF_HashPassword(32, "password", "salt", 3, 0, None, 64, 2, 4)
print toHex(str(hash))
