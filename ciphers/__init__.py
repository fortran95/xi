# -*- coding: utf-8 -*-

import struct,random,zlib
import blowfish, rijndael, twofish, serpent, xxtea

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
        cbc_mac = '\x00' * self.blocksize
        
        lastblock = iv
        for block in blocks:
            cblock = self.cipher.encrypt(block)
            nblock = self._block_xor(lastblock, cblock)

            cbc_mac = self.cipher.encrypt(self._block_xor(cbc_mac, block))

            lastblock = nblock
            result.append(nblock)

        result.append(cbc_mac) # APPEND the CBC_MAC value.

        return "".join(result)

    def decrypt(self,data):
        if data == False:
            return False
        
        datalen = len(data)
        if datalen % self.blocksize != 0:
            raise Exception("Invalid ciphertext input.")

        blocks = struct.unpack(self.splitcmd * (datalen / self.blocksize), data)
        blocks_max_index = len(blocks) - 1
        iv = blocks[0]
        cbc_mac = blocks[blocks_max_index]

        blocks = blocks[1:blocks_max_index]
        result = []

        lastblock = iv
        cbc_mac2 = '\x00' * self.blocksize

        for i in range(0,len(blocks)):
            nblock = blocks[i]
            cblock = self.cipher.decrypt(self._block_xor(lastblock,blocks[i]))
            cbc_mac2 = self.cipher.encrypt(self._block_xor(cbc_mac2, cblock))
            result.append(cblock)
            lastblock = nblock
#            result.append(self.cipher.decrypt(blocks[i]))
        if cbc_mac2 != cbc_mac:
            print "Because of a CBC_MAC integrity check failure, decryption cancelled."
            return False    # Data corrupted.

        return self.padder.depad("".join(result))


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
        if data == False:
            return False

        datalen = len(data)
        if datalen % self.blocksize != 0:
            raise Exception("Invalid ciphertext input. Data length: %d" % datalen)

        blocks = struct.unpack(self.splitcmd * (datalen / self.blocksize), data)
        result = []

        for block in blocks:
            result.append(self.cipher.decrypt(block))

        return self.padder.depad("".join(result))

class xipher(object):

    cipherlist = [
        [serpent.Serpent,   serpent.key_size,  serpent.block_size],
        [twofish.Twofish,   twofish.key_size,  twofish.block_size],
        [rijndael.Rijndael, rijndael.key_size, rijndael.block_size],
        [blowfish.Blowfish, blowfish.key_size, blowfish.block_size],
    ]
    def package(self, data, enpack=True):
        if len(self.packagekey) != xxtea.key_size:
            raise Exception("This packager requires a package key of %d bytes." % xxtea.key_size)
        tool = mode_cbc(xxtea.XXTEA(self.packagekey), xxtea.block_size)
        if enpack:
            return tool.encrypt(data)
        else:
            return tool.decrypt(data)

    encrypt_chain = []

    def get_version(self):
        return 1

    def __init__(self, key, packagekey=None):

        keylen = 0
        for x in self.cipherlist:
            keylen += x[1]

        if len(key) < keylen:
            raise Exception("Key too short. At least %d bytes required." % keylen)
        
        shifting_list = self.cipherlist[:]
        for i in range(0,len(self.cipherlist)):
            keyring = key[:]
            for x in shifting_list:
                cipher = x[0](keyring[0:x[1]])
                keyring = keyring[x[1]:]
                tool = mode_ecb(cipher, x[2])
                self.encrypt_chain.append(tool)
            shifting_first = shifting_list[0]
            shifting_list = shifting_list[1:]
            shifting_list.append(shifting_first)

        self.decrypt_chain = self.encrypt_chain[:]
        self.decrypt_chain.reverse()

        if packagekey == None:
            import hashlib
            self.packagekey = hashlib.md5(key).digest()
        else:
            self.packagekey = packagekey

    def encrypt(self, data):
        package_ctl = 0
        # Decide if use zlib
        compressed = zlib.compress(data,9)
        if len(compressed) / len(data) < 0.75:
            data = compressed.encode('base64')
            package_ctl += 1

        data = chr(package_ctl) + data
        for tool in self.encrypt_chain:
            data = tool.encrypt(data)
        
        return self.package(data)
    def decrypt(self, data):
        data = self.package(data,False)

        for tool in self.decrypt_chain:
#            print "data length: %d" % len(data)
            data = tool.decrypt(data)

        package_ctl = ord(data[0])
        data = data[1:]

        if package_ctl & 0x01:
            data = zlib.decompress(data.decode('base64'))
        return data

    def get_version(self):
        return 1


if __name__ == "__main__":
    key = "dsjkfajksdjflkasjfkjks" * 16
    text = open("rijndael.py").read()# + open("rijndael.py").read()"""
    xi = xipher(key)
#    print len(text)
    import time
    start = time.time()
    times = 1
#    for i in range(0,times):
    enc = xi.encrypt(text)

#    enc = enc[0:10] + 'a' + enc[11:]
    print "Plaintext Length:  %d" % len(text)
    print "Ciphertext Length: %d" % len(enc)
#    print enc.encode('base64')
#    print "Encrypted length = %d." % len(enc)
    dec = xi.decrypt(enc)
#    print dec
    print len(dec)
    if dec != text:
        raise Exception("Error decrypting.")
    stop = time.time()

    print "Time cost: %f" % (stop - start)
    print "Average speed: %f Bytes/s." % (len(text) * times * 2 / (stop - start))
