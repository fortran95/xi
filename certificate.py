# -*- coding: utf-8 -*-
"""
用户标识
公钥信息
    序号
    算法名
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

def tempfilename():
    return hashlib.md5(str(uuid.uuid3(uuid.uuid1(),str(uuid.uuid4())))).hexdigest()

class certificate(object):
    def __init__():
        pass
    def generate(**argv):
        # Will generate a new certificate. Compatiable to NERV-XI-001 Standard.
        
        # - subject
        # - 
        pass
    
if __name__ == "__main__":
    rsa1 = publickeyalgo._RSA()
    rsa1.generate(bits=1024)
    
    rsa2 = publickeyalgo._RSA()
    rsa2.generate(bits=1024)
    
    rsa1pub = publickeyalgo._RSA()
    rsa2pub = publickeyalgo._RSA()
    
    rsa1pub.load_publickey(rsa1.get_publickey())
    rsa2pub.load_publickey(rsa2.get_publickey())
    
    digest = '000'
    
    def encryptor(message,key):
        print "[%s] encrypted using key [%s](%d bits)." % (message,key.encode('hex'),len(key) * 8)
        return message.encode('hex')
    def decryptor(message,key):
        print "[%s] decrypted using key [%s]." % (message,key.encode('hex'))
        return message.decode('hex')
    
    message = 'dksfjakdsfjkasfsla;fdaslj'
    enc = rsa1pub.encrypt(message,encryptor)
    dec = rsa2.decrypt(enc,decryptor)
    print dec