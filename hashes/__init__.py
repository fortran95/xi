import hashlib
import whirlpool

class hash(object):
    _digest = ""
    _providers = {
        "whirlpool" : whirlpool.Whirlpool,
        "sha1"      : hashlib.sha1,
        "sha256"    : hashlib.sha256,
        "sha512"    : hashlib.sha512,
        "md5"       : hashlib.md5,
    }
    def __init__(self,algo,data):
        algo = algo.lower().strip()
        if self._providers.has_key(algo):
            self._digest = self._providers[algo](data).digest()
        else:
            raise Exception("Unrecognized hash algorithm.")
    def digest(self):
        return self._digest
    def hexdigest(self):
        return self.digest().encode('hex')
if __name__ == "__main__":
    for algo in hash._providers:
        print "hash '' with '%s' results:[%s]" % (algo, hash(algo,'').hexdigest())
