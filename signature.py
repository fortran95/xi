# -*- coding: utf-8 -*-

# 签名信息，是一个单独的类，本程序提供了产生、导出、导入、验证一个签名信息的方法。
import random
import bson as serializer

from hashes import *
from publickeyalgo import PublicKeyAlgorithm

class signature(object):

    def __init__(self,publickeystr):
        self.key = PublicKeyAlgorithm(publickeystr)

    def new(self,message,digestmod = 'whirlpool',raw=False):

        msghash = Hash(digestmod,message).digest()
        try:
            signraw = self.key.sign(msghash)
        except Exception,e:
            raise Exception("Unable to sign, error: %s" % e)
        
        signature = {'Type':'Signature','Digest_Method':digestmod,'Data':signraw}

        if raw:
            return signature
        else:
            return serializer.dumps(signature)

    def verify(self,signature,message):
        try:
            if type(signature) == type(""):
                j = serializer.loads(signature)
            else:
                j = signature
            if j['Type'] != 'Signature':
                raise Exception("This may not be a signature.")
            digestmod = j['Digest_Method']
            signraw = j['Data']

            msghash = Hash(digestmod,message).digest()
            
        except Exception,e:
            raise Exception("Bad format of signature, error: %s" % e)

        return self.key.verify(msghash,signraw)

if __name__ == "__main__":

    import publickeyalgo
    
    pk = publickeyalgo._EC()

    for c in pk._curves_name:
        try:
            privatekey = publickeyalgo._EC()

            privatekey.generate(curve=c)

            print privatekey.sign_limit()
        except:
            print "%s:--" % c

