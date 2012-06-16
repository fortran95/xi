import hashlib
import whirlpool

class Hash(object):
    _digest = None
    _hexdigest = None
    _providers = {
        "whirlpool" : [whirlpool.Whirlpool,     64], # verified
        "sha1"      : [hashlib.sha1,            64], # verified
        "sha256"    : [hashlib.sha256,          64], # verified
        "sha512"    : [hashlib.sha512,         128], # verified
        "md5"       : [hashlib.md5,             64], # verified 
    }
    def __init__(self,algo,data):
        algo = algo.lower().strip()
        if self._providers.has_key(algo):
            self._algo = self._providers[algo]
            self._digest = self._algo[0](data).digest()
            self._hexdigest = self._digest.encode('hex')
            self._data = data
        else:
            raise Exception("Unrecognized hash algorithm.")
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
    for algo in hash._providers:
        print "hash '' with '%s' results:[%s]" % (algo, hash(algo,'').hexdigest())
        print "HMAC with key '000': %s" % hash(algo,'').hmac('000')
