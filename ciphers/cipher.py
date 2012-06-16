# -*- coding: utf-8 -*-

import struct
import blowfish, rijndael, twofish, serpent

class padding(object):
    def __init__(self,blocksize):

        if blocksize > 256 or blocksize < 1:
            raise Exception("Cannot do such blocksize: %d" % blocksize)

        self.blocksize = blocksize
        
    def enpad(self,data):

        padlen = self.blocksize - (len(data) + 1) % self.blocksize

        return chr(padlen) + data + "\x00" * padlen

    def depad(self,data):

        padlen = ord(data[0:1])
        return data[1:len(data) - padlen]

class mode_ecb(object):
    def __init__(self,cipher,blocksize=16):

        self.cipher = cipher
        self.blocksize = blocksize
        self.padder = padding(blocksize)
        self.splitcmd = "%ds" % self.blocksize

    def encrypt(self,data):

        data = self.padder.enpad(data)
        datalen = len(data)
        
        blocks = struct.unpack(self.splitcmd * (datalen / self.blocksize), data)
        result = []
        
        for block in blocks:
            result.append(self.cipher.encrypt(block))
        
        return "".join(result)

    def decrypt(self,data):
        
        datalen = len(data)
        if datalen % self.blocksize != 0:
            raise Exception("Invalid ciphertext input.")

        blocks = struct.unpack(self.splitcmd * (datalen / self.blocksize), data)
        result = []

        for block in blocks:
            result.append(self.cipher.decrypt(block))

        return self.padder.depad("".join(result))

class xipher(object):

    def __init__(self, key):
        self.key = key

    def get_version(self):
        return 1


if __name__ == "__main__":
    key = "---This is a key of 32 bytes.---"
    cipher = rijndael.Rijndael(key)
    xi = mode_ecb(cipher,rijndael.block_size)
    text = open("rijndael.py").read()
    print xi.decrypt(xi.encrypt(text))

    exit()
    xi = xipher('hellodkkkkkkkkkkkkkkk')
    result = xi._depad(xi._enpad('helloaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
    print len(result)
    print result
