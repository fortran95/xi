import hashlib
import whirlpool

class Hash(object):
    _digest = None
    _hexdigest = None
    _providers = {
        # AlgoName      ProviderFunc         Blocksize/Bytes  OutputLength/Bytes
        "whirlpool" : [whirlpool.Whirlpool,     64,             64], # verified
        "sha1"      : [hashlib.sha1,            64,             20], # verified
        "sha224"    : [hashlib.sha224,          64,             28], # verified
        "sha256"    : [hashlib.sha256,          64,             32], # verified
        "sha384"    : [hashlib.sha384,         128,             48], # verified
        "sha512"    : [hashlib.sha512,         128,             64], # verified
        "md5"       : [hashlib.md5,             64,             16], # verified 
    }
    def __init__(self,algo=None,data=None):
        if algo != None and data != None:
            algo = algo.lower().strip()
            if self._providers.has_key(algo):
                self._algo = self._providers[algo]
                self._digest = self._algo[0](data).digest()
                self._hexdigest = self._digest.encode('hex')
                self._data = data
            else:
                raise Exception("Unrecognized hash algorithm.")
    def consult(self,maxbits):
        ret = {}
        for k in self._providers:
            outputbits = self._providers[k][2]
            if outputbits <= maxbits:
                if ret.has_key(outputbits):
                    ret[outputbits].append(k)
                else:
                    ret[outputbits] = [k,]
        return ret
    def recognizes(self,algoname):
        algoname = algoname.lower().strip()
        return self._providers.has_key(algoname)
    def digest(self):
        return self._digest
    def hexdigest(self):
        return self._hexdigest
    def hmac(self,key, raw=False):
        trans_5C = "".join(chr(x ^ 0x5c) for x in xrange(256))
        trans_36 = "".join(chr(x ^ 0x36) for x in xrange(256))
        blocksize = self._algo[1] 

        if len(key) > blocksize:
            key = self._algo[0](key).digest()
        key += chr(0) * (blocksize - len(key))
        o_key_pad = key.translate(trans_5C)
        i_key_pad = key.translate(trans_36)
        
        hmacdigest = self._algo[0](o_key_pad + self._algo[0](i_key_pad + self._data).digest()).digest()

        if raw:
            return hmacdigest
        else:
            return hmacdigest.encode('hex')

if __name__ == "__main__":
    """
    for algo in Hash._providers:
        print "hash '' with '%s' results:[%s]" % (algo, Hash(algo,'').hexdigest())
        import hmac
        print hmac.HMAC('','',hashlib.sha384).hexdigest() == Hash('sha384','').hmac('',False)
    """
    print Hash().consult(50)
