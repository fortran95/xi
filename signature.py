# -*- coding: utf-8 -*-

# 签名信息，是一个单独的类，本程序提供了产生、导出、导入、验证一个签名信息的方法。

from hashes import *
from publickeyalgo import PublicKeyAlgorithm
import json,random

class signature(object):

    def __init__(self,publickeystr):
        self.key = PublicKeyAlgorithm(publickeystr)

    def new(self,message,digestmod = 'whirlpool',raw=False):
        hmackey = ''
        for i in range(0,64):
            hmackey += chr(random.randint(0,255))

        msghash = Hash(digestmod,message).hmac(hmackey,True)
        try:
            signraw = self.key.sign(msghash)
        except Exception,e:
            raise Exception("Unable to sign, error: %s" % e)
        
        signature = {'Type':'Signature','HMAC_Key':hmackey.encode('base64'),'Digest_Method':digestmod,'Data':signraw.encode('base64')}

        if raw:
            return signature
        else:
            return json.dumps(signature)

    def verify(self,signature,message):
        try:
            if type(signature) == type(""):
                j = json.loads(signature)
            else:
                j = signature
            if j['Type'] != 'Signature':
                raise Exception("This may not be a signature.")
            digestmod = j['Digest_Method']
            signraw = j['Data'].decode('base64')
            if j.has_key('HMAC_Key'):
                msghash = Hash(digestmod,message).hmac(j['HMAC_Key'].decode('base64'),True)
            else:
                msghash = Hash(digestmod,message).digest()
        except Exception,e:
            raise Exception("Bad format of signature, error: %s" % e)

        return self.key.verify(msghash,signraw)

if __name__ == "__main__":

    import publickeyalgo

    privatekey = publickeyalgo._EC()
    privatekey.generate(curve=734)

    privatekey_str = privatekey.get_privatekey()

    signer = signature(privatekey_str)
    signature = signer.new('dkfjaskfsjk')

    print signer.verify(signature,'dkfjaskfsjk')

