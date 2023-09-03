# Copyright (C) 2014 by Stephen Bradshaw
#
# SHA1 and SHA2 generation routines from SlowSha https://code.google.com/p/slowsha/
# which is: Copyright (C) 2011 by Stefano Palazzo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

'''
    Pure Python Hash Length Extension module.

    Currently supports SHA1, SHA256 and SHA512, more algorithms will
    be added in the future.


    Create a hash by calling one of the named constuctor functions:
    sha1(), sha256(), and sha512(), or by calling new(algorithm).

    The hash objects have the following methods:

    hash(message):      

        Feeds data into the hash function using the normal interface.

    extend(appendData, knownData, secretLength, startHash):

        Performs a hash length extension attack.  Returns the bytestring to
        use when appending data.

    hexdigest():        

        Returns a hexlified version of the hash output.


    Assume you have a hash generated from an unknown secret value concatenated with
    a known value, and you want to be able to produce a valid hash after appending 
    additional data to the known value.

    If the hash algorithm used is one of the vulnerable functions implemented in
    this module, is is possible to achieve this without knowing the secret value
    as long as you know (or can guess, perhaps by brute force) the length of that
    secret value.  This is called a hash length extension attack. 

    Given an existing sha1 hash value '52e98441017043eee154a6d1af98c5e0efab055c',
    known data of 'hello', an unknown secret of length 10 and data you wish
    to append of 'file', you would do the following to perform the attack:
    
    >>> import hlextend
    >>> sha = hlextend.new('sha1')
    >>> print sha.extend(b'file', b'hello', 10, '52e98441017043eee154a6d1af98c5e0efab055c')
    b'hello\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xfile'
    >>> print sha.hexdigest()
    c60fa7de0860d4048a3bfb36b70299a95e6587c9

   The unknown secret (of length 10), that when hashed appended with 'hello' produces
   a SHA1 hash of '52e98441017043eee154a6d1af98c5e0efab055c', will then produce 
   a SHA1 hash of 'c60fa7de0860d4048a3bfb36b70299a95e6587c9' when appended with the output 
   from the extend function above.
   
   If you are not sure of the exact length of the secret value, simply try the above
   multiple times specifying different values for the length to brute force.
'''


from re import match
from math import ceil
from typing import Union


__version__ = "0.2"


class Hash(object):
    '''Parent class for hash functions'''

    def hash(self, message):
        '''Normal input for data into hash function'''

        length = bin(len(message) * 8)[2:].rjust(self._blockSize, "0")

        while len(message) > self._blockSize:
            self._transform(''.join([bin(a)[2:].rjust(8, "0")
                            for a in message[:self._blockSize]]))
            message = message[self._blockSize:]

        message = self.__hashBinaryPad(message, length)

        for a in range(len(message) // self._b2):
            self._transform(message[a * self._b2:a * self._b2 + self._b2])

    def extend(self, appendData, knownData, secretLength, startHash):
        '''Hash length extension input for data into hash function'''
        self.__checkInput(secretLength, startHash)
        self.__setStartingHash(startHash)

        extendLength = self.__hashGetExtendLength(
            secretLength, knownData, appendData)

        message = appendData

        while len(message) > self._blockSize:
            self._transform(''.join([bin(a)[2:].rjust(8, "0")
                            for a in message[:self._blockSize]]))
            message = message[self._blockSize:]

        message = self.__hashBinaryPad(message, extendLength)

        for i in range(len(message) // self._b2):
            self._transform(message[i * self._b2:i * self._b2 + self._b2])

        return self.__hashGetPadData(secretLength, knownData, appendData)

    def hexdigest(self):
        '''Outputs hash data in hexlified format'''
        return ''.join([(('%0' + str(self._b1) + 'x') % (a)) for a in self.__digest()])

    def __init__(self):
        # pre calculate some values that get used a lot
        self._b1 = self._blockSize/8
        self._b2 = self._blockSize*8

    def __digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match('^_h\d+$', a)]

    def __setStartingHash(self, startHash):
        c = 0
        hashVals = [int(startHash[a:a+int(self._b1)], base=16)
                    for a in range(0, len(startHash), int(self._b1))]
        for hv in [a for a in dir(self) if match('^_h\d+$', a)]:
            self.__setattr__(hv, hashVals[c])
            c += 1

    def __checkInput(self, secretLength, startHash):
        if not isinstance(secretLength, int):
            raise TypeError('secretLength must be a valid integer')
        if secretLength < 1:
            raise ValueError('secretLength must be grater than 0')
        if not match('^[a-fA-F0-9]{' + str(len(self.hexdigest())) + '}$', startHash):
            raise ValueError('startHash must be a string of length ' +
                             str(len(self.hexdigest())) + ' in hexlified format')

    def __byter(self, byteVal):
        '''Helper function to return usable values for hash extension append data'''
        if byteVal < 0x20 or byteVal > 0x7e:
            return '\\x%02x' % (byteVal)
        else:
            return chr(byteVal)

    def __binToByte(self, binary) -> bytearray:
        return int(binary, 2).to_bytes(len(binary) // 8, byteorder='big')

    def __hashGetExtendLength(self, secretLength, knownData, appendData):
        '''Length function for hash length extension attacks'''
        # binary length (secretLength + len(knownData) + size of binarysize+1) rounded to a multiple of blockSize + length of appended data
        originalHashLength = int(ceil(
            (secretLength+len(knownData)+self._b1+1)/float(self._blockSize)) * self._blockSize)
        newHashLength = originalHashLength + len(appendData)
        return bin(newHashLength * 8)[2:].rjust(self._blockSize, "0")

    def __hashGetPadData(self, secretLength, knownData, appendData):
        '''Return append value for hash extension attack'''
        originalHashLength = bin(
            (secretLength+len(knownData)) * 8)[2:].rjust(self._blockSize, "0")
        padData = ''.join(bin(i)[2:].rjust(8, "0")
                          for i in knownData) + "1"
        padData += "0" * (((self._blockSize*7) - (len(padData)+(secretLength*8)) %
                          self._b2) % self._b2) + originalHashLength
        
        return self.__binToByte(padData) + appendData

    def __hashBinaryPad(self, message, length):
        '''Pads the final blockSize block with \x80, zeros, and the length, converts to binary'''
        out_msg = ''
        
        for i in message:
            out_msg += bin(i)[2:].rjust(8, "0")
        
        out_msg += "1"
        out_msg += "0" * (((self._blockSize*7) - len(out_msg) % self._b2) % self._b2) + length
        
        return out_msg


class SHA1 (Hash):

    _h0, _h1, _h2, _h3, _h4, = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    _blockSize = 64

    def _transform(self, chunk):

        def lrot(x, n): return (x << n) | (x >> (32 - n))
        w = []

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                     & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in range(80):

            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6

            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff


class SHA256 (Hash):

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    _blockSize = 64

    def _transform(self, chunk):
        def rrot(x, n): return (x >> n) | (x << (32 - n))
        w = []

        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in range(16, 64):
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in range(64):
            s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~ e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
        self._h5 = (self._h5 + f) & 0xffffffff
        self._h6 = (self._h6 + g) & 0xffffffff
        self._h7 = (self._h7 + h) & 0xffffffff


class SHA512 (Hash):

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)

    _blockSize = 128

    def _transform(self, chunk):

        def rrot(x, n): return (x >> n) | (x << (64 - n))
        w = []

        k = [
            0x428a2f98d728ae22, 0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019,
            0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
            0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210,
            0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001,
            0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910,
            0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60,
            0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9,
            0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

        for j in range(len(chunk) // 64):
            w.append(int(chunk[j * 64:j * 64 + 64], 2))

        for i in range(16, 80):
            s0 = rrot(w[i - 15], 1) ^ rrot(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = rrot(w[i - 2], 19) ^ rrot(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffffffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in range(80):
            s0 = rrot(a, 28) ^ rrot(a, 34) ^ rrot(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 14) ^ rrot(e, 18) ^ rrot(e, 41)
            ch = (e & f) ^ ((~ e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffffffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffffffffffff

        self._h0 = (self._h0 + a) & 0xffffffffffffffff
        self._h1 = (self._h1 + b) & 0xffffffffffffffff
        self._h2 = (self._h2 + c) & 0xffffffffffffffff
        self._h3 = (self._h3 + d) & 0xffffffffffffffff
        self._h4 = (self._h4 + e) & 0xffffffffffffffff
        self._h5 = (self._h5 + f) & 0xffffffffffffffff
        self._h6 = (self._h6 + g) & 0xffffffffffffffff
        self._h7 = (self._h7 + h) & 0xffffffffffffffff


def new(algorithm) -> Union[SHA1, SHA256, SHA512]:
    obj = {
        'sha1': SHA1,
        'sha256': SHA256,
        'sha512': SHA512,
    }[algorithm]()
    return obj


def sha1():
    ''' Returns a new sha1 hash object '''
    return new('sha1')


def sha256():
    ''' Returns a new sha256 hash object '''
    return new('sha256', )


def sha512():
    ''' Returns a new sha512 hash object '''
    return new('sha512', )


__all__ = ('sha1', 'sha256', 'sha512')
