# -*- coding: utf-8 -*-

import struct,random,zlib,math,copy
import blowfish, rijndael, twofish, serpent, xxtea

class xipher(object):

    cipherlist = [
        [serpent.Serpent,   serpent.key_size,  ],
        [twofish.Twofish,   twofish.key_size   ],
        [rijndael.Rijndael, rijndael.key_size  ],
        [xxtea.XXTEA,       xxtea.key_size,    ],
#        [blowfish.Blowfish, blowfish.key_size, blowfish.block_size],
    ]
    blocksize  = 16
    ivsize = 8

    encrypt_chain = []

    def __init__(self, key, packagekey=None):

        keylen = 0
        for x in self.cipherlist:
            keylen += x[1]

        if len(key) < keylen:
            raise Exception("Key too short. At least %d bytes required." % keylen)
        
        shifting_list = self.cipherlist[:]
        self.encrypt_chain = []
        for i in range(0,len(self.cipherlist)):
            keyring = key[:]
            for x in shifting_list:
                #print "New Cipher:%20s with key: %s" % (str(x[0]),keyring[0:x[1]].encode('hex'))
                
                self.encrypt_chain.append((x[0],keyring[0:x[1]]))

                keyring = keyring[x[1]:]
                #break
            #break
            shifting_first = shifting_list[0]
            shifting_list = shifting_list[1:]
            shifting_list.append(shifting_first)

        if packagekey == None:
            import hashlib
            self.packagekey = hashlib.sha256(key).digest()
        else:
            self.packagekey = packagekey
    def _encrypt_block(self,data):
        length = len(self.encrypt_chain)
        #print "Encrypt Block: %s" % data.encode('hex')
        #print "Encrypt Chain has %d items." % length
        for i in range(0,length):
            #for tool in self.encrypt_chain:
            tool = self.encrypt_chain[i]
            data = tool[0](tool[1]).encrypt(data)
        return data
    def _xor_stream(self,stream,data):
        datalen = len(data)
        if len(stream) < datalen:
            raise Exception("Length of bitstream is not sufficient.")
        result = ''
        for i in range(0,datalen):
            result += chr(ord(stream[i]) ^ ord(data[i]))
        return result
    def keystream(self,times,iv):
        #print "Generating keystream of %d times basing on [%s]." % (times,iv.encode('hex'))
        ret = ''
        for i in range(0,times):
            block = "%8s%8s" % (iv,hex(i)[2:])
            #print block
            ciblk = self._encrypt_block(block)
            #print "%s -> %s" % (block.encode('hex'),ciblk.encode('hex'))
            ret += ciblk

        #print "KeyStream:" + ret.encode('hex')
        return ret
    def encrypt(self, data):    # Use CFB
        iv = ''
        for i in range(0,self.ivsize):
            iv += chr(random.randint(0,255))
        iv0 = iv[:]
        
        # generate CFB keystream
        datalen = len(data)

        times = datalen / self.blocksize
        if datalen % self.blocksize != 0:
            times += 1

        keystream = self.keystream(times,iv)
        
        result = str(iv0) + str(self._xor_stream(keystream,data))
        
        return result
    def decrypt(self,data):
        # generate CFB iv
        iv = data[0:self.ivsize].strip()
        
        data = data[self.ivsize:]
        # generate CFB keystream
        datalen = len(data)

        times = datalen / self.blocksize
        if datalen % self.blocksize != 0:
            times += 1

        keystream = self.keystream(times,iv)
                
        result = self._xor_stream(keystream,data)
        return result

    def get_version(self):
        return 1

def encryptor(key,data):
    xi1 = xipher(key[:])
    return xi1.encrypt(data)

def decryptor(key,data):
    xi2 = xipher(key[:])
    return xi2.decrypt(data)

if __name__ == "__main__":    
    key = '\x10' * 128
#    for i in range(0,128):
#        key += chr(random.randint(0,255))
    text = """
    ***** * ' * 3
   
    
    xi1 = xipher(key)
    xi2 = xipher(key)

    #enc1 = xi1.encrypt('text')
    #enc1 = xi1.encrypt(text)
    enc2 = xi2.encrypt(text)

    #print xi2.decrypt(enc1)
    print xi1.decrypt(enc2)
    """
    #exit()
    #print xi2.decrypt(xi1.encrypt(text))
    enc = encryptor(key,text)
    #print enc
    print '- ' * 40
    dec = decryptor(key,enc)

    print dec == text
