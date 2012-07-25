# -*- coding: utf-8 -*-

import struct,random,zlib,math,copy
import blowfish, rijndael, twofish, serpent, xxtea
import _derivekey

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

    def __init__(self, key):

        keylen = 0
        for x in self.cipherlist:
            keylen += x[1]

        if len(key) < keylen:
            raise Exception("Key too short. At least %d bytes required." % keylen)
        
        shifting_list = self.cipherlist[:]
        self.encrypt_chain = []
        derivedkey = key[:]
        for i in range(0,len(self.cipherlist)):
            keyring = derivedkey[:]
            for x in shifting_list:
                #print "New Cipher:%20s with key: %s" % (str(x[0]),keyring[0:x[1]].encode('hex'))
                
                self.encrypt_chain.append((x[0],keyring[0:x[1]]))

                keyring = keyring[x[1]:]
                #break
            #break
            #print ""
            derivedkey = _derivekey.derive_key(derivedkey)
            shifting_first = shifting_list[0]
            shifting_list = shifting_list[1:]
            shifting_list.append(shifting_first)

    def _encrypt_block(self,data):
        length = len(self.encrypt_chain)
        #print "Encrypt Block: %s" % data.encode('hex')
        #print "Encrypt Chain has %d items." % length
        data0 = data[:]
        for i in range(0,length):
            #for tool in self.encrypt_chain:
            tool = self.encrypt_chain[i]
            data = tool[0](tool[1]).encrypt(data)
        #print data0.encode('hex') + ' -> ' + data.encode('hex')
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
        block = ''
        for i in range(0,times):
            block += "%8s%8s" % (iv,hex(i)[2:])

        ciblk = self._encrypt_block(block)

        #print "KeyStream:" + ciblk.encode('hex')
        return ciblk
    def encrypt(self, data):    # Use CFB
        rand = ''
        for i in range(0,self.blocksize / 4 * 3):
            rand += chr(random.randint(0,255))
        rand = rand.encode('base64')[0:self.blocksize]

        iv = hex(abs(int(zlib.crc32(rand + data))))[2:2+self.ivsize]
        if len(iv) < self.ivsize:
            iv += (self.ivsize - len(iv)) * '*'
        
        iv0 = iv[:]
        
        # generate CFB keystream
        datalen = len(data)

        times = datalen / self.blocksize
        if datalen % self.blocksize != 0:
            times += 1

        keystream = self.keystream(times,iv)
        #print "KeyStream:" + keystream.encode('hex')
        
#        teststart = time.time()
        result = rand + str(iv0) + str(self._xor_stream(keystream,data))
#        testend = time.time()

#        print "Xor Time Cost: %f seconds." % (testend - teststart)
        
        return result
    def decrypt(self,data):
        rand = data[0:self.blocksize]
        data = data[self.blocksize:]
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
        digest = hex(abs(int(zlib.crc32(rand + result))))[2:10]
        #if len(digest) < self.ivsize:
        #    digest += (self.ivsize - len(iv)) * '*'
         

        if digest == iv[0:len(digest)]:
            #print 'verified.'
            return result
        else:
            raise Exception("Cannot decrypt. Data corrupted or incorrect key.")

    def get_version(self):
        return 1

def encryptor(key,data):
    xi1 = xipher(key[:])
    return xi1.encrypt(data)

def decryptor(key,data):
    xi2 = xipher(key[:])
    return xi2.decrypt(data)

if __name__ == "__main__":    
    import time

    fail = 0
    job = 0

    times = 50
    data = []
    for i in range(0,times):
        key = ''
        text = ''
        for j in range(0,128):
            key += chr(random.randint(0,255))
        for j in range(0,random.randint(128,256)):
            text += chr(random.randint(0,255))
        xi1 = xipher(key)
        xi2 = xipher(key)
        data.append((xi1,xi2,text))

    b = time.time()
    for t in range(0,times):

        try:
            enc1 = data[t][0].encrypt(data[t][2])
            dec1 = data[t][1].decrypt(enc1)
            if data[t][2] != dec1:
                raise Exception('.')
            job += len(data[t][2])
        except Exception,e:
            print '****'
            fail += 1
        if t % 100 == 0:
            print t
    e = time.time()
    print "Failed %d times of 10000 tests." % fail
    print "Average speed: %f bytes / second." % (job / (e-b))
    """
    #exit()
    #print xi2.decrypt(xi1.encrypt(text))
    import time
    a = time.time()
    c = 1000
    for i in range(0,c):
        enc = encryptor(key,text)
        #print enc
        dec = decryptor(key,enc)
        if dec != text:
            print "-------- ERROR! --------"
            print key.encode('hex')
            print enc[0:16].encode('hex')
    b = time.time()

    print "Average is: %f" % (c * 1.0 * len(text) / (b-a))
    """
