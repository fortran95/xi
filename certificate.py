# -*- coding: utf-8 -*-
"""
用户标识
公钥信息
    公钥环
        参数：值，参数：值……
            对于ECDH，需要给定：
                1)曲线参数。因为只有同种曲线才能进行密钥交换。
                2)密钥的公钥值
            对于
        
--------------------------------------------------------------------------------    
指纹（根据以上全部信息和规定格式）
    指纹算法
    hash值
证书ID：指纹的某个hash

以上信息的数字签名，格式为：
    HMAC-KEY
    签名者的证书ID
    签名日期
    有效日期
    签名用的HASH算法
    签名者的签名；对以下内容进行签名
        证书的指纹
        签名日期
        有效日期
"""
import random,time,os,json,uuid,hashlib
import publickeyalgo

def hashable_json(input):
    return json.dumps(input,sort_keys=True,indent=0,ensure_ascii=True).strip()

class certificate(object):
    subject = None
    keys = None
    is_ours = False
    signatures = None
    
    def __init__(self):
        pass
    def generate(self,subject,**argv):
        # Will generate a new certificate. Compatiable to NERV-XI-001 Standard.
        
        # - subject
        subject = subject.strip()
        if len(subject) > 512 or len(subject) < 3:
            raise Exception("Certificate subject is not valid.")
        self.subject = subject
        
        # - pubkeyring        
        key_ec = publickeyalgo._EC()
        if argv.has_key('curve'):
            key_ec.generate(curve=argv['curve'])
        else:
            key_ec.generate()
        
        key_rsa = publickeyalgo._RSA()
        if argv.has_key('bits'):
            key_rsa.generate(bits=argv['bits'])
        else:
            key_rsa.generate()
        
        self.keys = [key_ec,key_rsa]
        self.is_ours = True
        
        # - clear others
        self.signatures = None
        
        # After generated, load this cert. into the instance.
    
    def get_public_text(self):
        # This will generate a publishable certificate text.
        # - subject
        # - pubkeyring
        pubkeyring = {}
        keyindex = 1
        for k in self.keys:
            keydata = k.get_publickey(raw=True)
            pubkeyring[keyindex] = keydata
            keyindex += 1
        baseinfo = {
                'Version': '1',
                'Subject': self.subject,
                'Public_Key_Ring':pubkeyring,
            }
        
        # format json.
        hash_source = hashable_json(baseinfo)
        j = {
            'Basic':baseinfo,
            'Finger_Print':[
                    {
                        'Algorithm': 'SHA512',
                        'Hash': hashlib.sha512(hash_source).digest().encode('base64')
                    },
                    {
                        'Algorithm': 'MD5',
                        'Hash': hashlib.md5(hash_source).digest().encode('base64')
                    },
                    {
                        'Algorithm': 'SHA1',
                        'Hash': hashlib.sha1(hash_source).digest().encode('base64')
                    },
                ],
            'Signatures':{}
            }
        
        return json.dumps(j,indent=2,sort_keys=True)
if __name__ == "__main__":
    cert = certificate()
    cert.generate('NERV',bits=1024)
    print "-" * 80
    print cert.get_public_text()