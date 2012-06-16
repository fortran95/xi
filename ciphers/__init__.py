# -*- coding: utf-8 -*-

import struct,random,zlib
import blowfish, rijndael, twofish, serpent

class padding(object):
    def __init__(self,blocksize):

        if blocksize > 256 or blocksize < 1:
            raise Exception("Cannot do such blocksize: %d" % blocksize)

        self.blocksize = blocksize
        
    def enpad(self,data):

        padlen = self.blocksize - len(data) % self.blocksize

        if padlen == self.blocksize:
            return data
        else:
            return data + chr(padlen) * padlen

    def depad(self,data):

        padlen = ord(data[-1:])

        padstr = data[-padlen:]

        if padstr == chr(padlen) * padlen:
            return data[0:len(data) - padlen]
        else:
            return data

class mode_cbc(object):
    def __init__(self,cipher,blocksize=16):

        self.cipher = cipher
        self.blocksize = blocksize
        self.padder = padding(blocksize)
        self.splitcmd = "%ds" % self.blocksize
    def _block_xor(self,block1, block2):
        ret = ''
        for i in range(0,self.blocksize):
            ret += chr( ord(block1[i:i+1]) ^ ord(block2[i:i+1]) )
        return ret

    def encrypt(self,data):

        data = self.padder.enpad(data)
        datalen = len(data)
        
        blocks = struct.unpack(self.splitcmd * (datalen / self.blocksize), data)
        iv = ''
        for i in range(0,self.blocksize):
            iv += chr(random.randint(0,255))
        result = [iv,]
        
        lastblock = iv
        for block in blocks:
            cblock = self.cipher.encrypt(block)
            nblock = self._block_xor(lastblock, cblock)
            lastblock = nblock
            result.append(nblock)
        
        return "".join(result)

    def decrypt(self,data):
        
        datalen = len(data)
        if datalen % self.blocksize != 0:
            raise Exception("Invalid ciphertext input.")

        blocks = struct.unpack(self.splitcmd * (datalen / self.blocksize), data)
        iv = blocks[0]
        blocks = blocks[1:]
        result = []

        lastblock = iv
        for i in range(0,len(blocks)):
            nblock = blocks[i]
            result.append(self.cipher.decrypt(self._block_xor(lastblock,blocks[i])))
            lastblock = nblock
#            result.append(self.cipher.decrypt(blocks[i]))

        return self.padder.depad("".join(result))


class mode_ecb(object):
    def __init__(self,cipher,blocksize=16):

        self.cipher = cipher
        self.blocksize = blocksize
        self.padder = padding(blocksize)
        self.splitcmd = "%ds" % self.blocksize

    def encrypt(self,data):

        data = zlib.compress(data)

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

        return zlib.decompress(self.padder.depad("".join(result)))

class xipher(object):

    cipherlist = [
        [serpent.Serpent,   serpent.key_size,  serpent.block_size,  mode_ecb],
        [twofish.Twofish,   twofish.key_size,  twofish.block_size,  mode_ecb],
        [rijndael.Rijndael, rijndael.key_size, rijndael.block_size, mode_ecb],
        [blowfish.Blowfish, blowfish.key_size, blowfish.block_size, mode_cbc],
    ]
    encrypt_chain = []

    def get_version(self):
        return 1

    def __init__(self, key):

        keylen = 0
        for x in self.cipherlist:
            keylen += x[1]

        if len(key) < keylen:
            raise Exception("Key too short. At least %d bytes required." % keylen)
        
        for x in self.cipherlist:
            cipher = x[0](key[0:x[1]])
            key = key[x[1]:]
            tool = x[3](cipher, x[2])
            self.encrypt_chain.append(tool)

        self.decrypt_chain = self.encrypt_chain[:]
        self.decrypt_chain.reverse()

    def encrypt(self, data):
        for tool in self.encrypt_chain:
            data = tool.encrypt(data)
        return data
    def decrypt(self, data):
        for tool in self.decrypt_chain:
            data = tool.decrypt(data)
        return data

    def get_version(self):
        return 1


if __name__ == "__main__":
    key = "dsjkfajksdjflkasjfkjks" * 16
    text = open("blowfish.py").read() + open("rijndael.py").read()
    xi = xipher(key)
    print len(text)
    import time
    start = time.time()
    times = 1
    for i in range(0,times):
        enc = xi.encrypt(text)

        print len(enc)
#    print enc.encode('base64')
#    print "Encrypted length = %d." % len(enc)
        dec = xi.decrypt(enc)
#    print dec
#    print len(dec)
        if dec != text:
            raise Exception("Error decrypting.")
    stop = time.time()

    print "Time cost: %f" % (stop - start)
    print "Average speed: %f Bytes/s." % (len(text) * times / (stop - start))
