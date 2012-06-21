# -*- coding: utf-8 -*-

# ǩ����Ϣ����һ���������࣬�������ṩ�˲��������������롢��֤һ��ǩ����Ϣ�ķ�����

from hashes import *
from publickeyalgo import PublicKeyAlgorithm
import json

class signature(object):

    def __init__(self,publickeystr):
        self.key = PublicKeyAlgorithm(publickeystr)

    def new(self,message,digestmod = 'whirlpool'):
        msghash = Hash(digestmod,message).digest()
        try:
            signraw = self.key.sign(msghash)
        except Exception,e:
            raise Exception("Unable to sign, error: %s" % e)

        signstr = json.dumps({'Type':'signature','Digest_Method':digestmod,'Data':signraw})

        return signstr

    def verify(self,signature,message):
        try:
            j = json.loads(signature)
            if j['Type'] != 'signature':
                raise Exception("This may not be a signature.")
            digestmod = j['Digest_Method']
            signraw = j['Data']
        except Exception,e:
            raise Exception("Bad format of signature, error: %s" % e)
        msghash = Hash(digestmod,message).digest()

        return self.key.verify(msghash,signraw)

if __name__ == "__main__":

    import publickeyalgo

    privatekey = publickeyalgo._EC()
    privatekey.generate(curve=734)

    privatekey_str = privatekey.get_privatekey()

    signer = signature(privatekey_str)
    signature = signer.new('dkfjaskfsjk')

    print signer.verify(signature,'dkfjaskfsjk')

