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
    有效日期（证书的有效期由上级确定，没有签名的证书本身就是可疑的）
    签名用的HASH算法
    签名者的签名；对以下内容进行签名
        证书的指纹
        签名日期
        有效日期
"""
import random,time,os,json,uuid,shelve
import publickeyalgo
from hashes import Hash

def hashable_json(input):
    return json.dumps(input,sort_keys=True,indent=0,ensure_ascii=True).strip()

class certificate(object):
    subject = None
    keys = None
    signatures = None
    is_ours = False
    signatures = None
    
    def __init__(self):
        pass
    def generate(self,subject,**argv):
        # Will generate a new certificate. Compatiable with NERV-XI-001 Standard.
        
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

    # TODO 提供导出和导入私有证书的方法。
    def save_private_text(self,filename):
        if not self.is_ours:
            raise Exception("Trying to save private info of a public certificate.")

        savesh = shelve.open(filename,writeback=True)
        savesh.clear()

        # save basic info
        savesh['Title']   = 'Xi_Certificate_Private'
        savesh['Basic']   = {
                "Public_Key_Ring":{},
                "Subject":self.subject,
                "Version":'1',
            }
       
        # save self.keys
        keyindex = 1
        for k in self.keys:
            keydata = k.get_privatekey(raw=True)
            savesh['Basic']['Public_Key_Ring'][keyindex] = keydata
            keyindex += 1

        # save signatures
        # TODO 

        # final
        savesh.sync()
        savesh.close()
    def load_private_text(self,filename):
        loadsh = shelve.open(filename)
        try:
            if loadsh['Title'] != 'Xi_Certificate_Private':
                raise Exception("Seems not a Xi Project Certificate Private info.")

            # Read subject, version and others

            basic = loadsh['Basic']
            basic_version = basic['Version']
            basic_subject = basic['Subject']
            basic_public_key_ring = basic['Public_Key_Ring']

            certid = Hash('md5',hashable_json(basic)).hexdigest()

            # Try to load public keys

            basic_prvkey_sensible = True
            eckey = publickeyalgo._EC()
            rsakey = publickeyalgo._RSA()
            try:
                for key in basic_public_key_ring:

                    prvkey = basic_public_key_ring[key]
                    if prvkey['type'] == 'EC_Private_Key':
                        ret = eckey.load_privatekey(json.dumps(prvkey))
                    elif prvkey['type'] == 'RSA_Private_Key':
                        ret = rsakey.load_privatekey(json.dumps(prvkey))
                    basic_prvkey_sensible = basic_prvkey_sensible and ret

            except Exception,e:
                print "Error occured: %s" % e
                basic_prvkey_sensible = False
            if not basic_prvkey_sensible:
                raise Exception("This ceritificate's private key info is non-sense.")
            if not ( eckey._key != None and rsakey._key != None ):
                raise Exception("This certificate has insufficient private key info.")

            # TODO check signatures, consult reliability.

            # Now load this certificate.

            self.is_ours = True
            self.keys = [eckey, rsakey]
            self.subject = basic_subject

            print "Certificate verified and loaded."
            return True
                        
        except Exception,e:
            raise Exception("Certificate format is bad: %s" % e)


    # TODO 提供使用证书进行加密和签署的方法。用于给证书持有者传递信息，以及让证书持有者自己签署信息。
    # XXX  具体来说，需要提供：
    #    XXX 用自己的私人证书产生给一个来自公共域的证书的签名信息(此人给出信任等级)
    #    XXX 向一个（公有或者私有的）证书中插入来自外人的签名（验证并储存，然后可以通过get_public_text或者save_private_text储存
    
    # XXX  证书如果没有签名，就是可疑的。提供签名和验证签名的方法。
    #        签名信息应当被单独列入一个类，提供签名的产生、导出、验证等方法。验证签名需要相应的公钥证书。

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
            'ID'   :Hash('md5',hash_source).hexdigest(),
            'Title':'Xi_Certificate',
            'Basic':baseinfo,
            'Finger_Print':[
                    {
                        'Algorithm': 'SHA512',
                        'Hash': Hash('sha512',hash_source).digest().encode('base64')
                    },
                    {
                        'Algorithm': 'MD5',
                        'Hash': Hash('md5',hash_source).digest().encode('base64')
                    },
                    {
                        'Algorithm': 'SHA1',
                        'Hash': Hash('sha1',hash_source).digest().encode('base64')
                    },
                    {
                        'Algorithm': 'WHIRLPOOL',
                        'Hash': Hash('whirlpool',hash_source).digest().encode('base64')
                    },
                ],
            'Signatures':{}
            }
        # return
        return json.dumps(j,indent=2,sort_keys=True)
    def load_public_certificate(self,text):
        try:
            j = json.loads(text)
            if j['Title'] != 'Xi_Certificate':
                raise Exception("Seems not a Xi Project Certificate.")

            # Read subject, version and others

            basic = j['Basic']
            basic_version = basic['Version']
            basic_subject = basic['Subject']
            basic_public_key_ring = basic['Public_Key_Ring']

            fingerprint = j['Finger_Print']
            certid = j['ID']

            # Try to load public keys

            basic_pubkey_sensible = True
            eckey = publickeyalgo._EC()
            rsakey = publickeyalgo._RSA()
            try:
                for key in basic_public_key_ring:

                    pubkey = basic_public_key_ring[key]

                    if pubkey['type'] == 'EC_Public_Key':
                        ret = eckey.load_publickey(json.dumps(pubkey))
                    elif pubkey['type'] == 'RSA_Public_Key':
                        ret = rsakey.load_publickey(json.dumps(pubkey))
                    basic_pubkey_sensible = basic_pubkey_sensible and ret
            except Exception,e:
                print "Error occured: %s" % e
                basic_pubkey_sensible = False
            if not basic_pubkey_sensible:
                raise Exception("This ceritificate's public key info is non-sense.")
            if not ( eckey._pubkey != None and rsakey._pubkey != None ):
                raise Exception("This certificate has insufficient public key info.")

            # Verify Integrity

            hash_source = hashable_json(basic)
            hash_recognized = False
            for fpinfo in fingerprint:
                if Hash().recognizes(fpinfo['Algorithm']):
                    hash_recognized = True
                    calchash = Hash(fpinfo['Algorithm'],hash_source).digest().encode('base64')
                    if calchash != fpinfo['Hash']:
                        raise Exception("Certificate has invalid hash, cannot verify its INTERGRITY.")
            if not hash_recognized:
                raise Exception("Cannot verify INTERGRITY of this certificate.")

            wanted_id = Hash('md5',hash_source).hexdigest()
            if wanted_id != certid:
                raise Exception("Certificate ID do not match its content.")

            # TODO check signatures, consult reliability.

            # Now load this certificate.

            self.is_ours = False
            self.keys = [eckey, rsakey]
            self.subject = basic_subject

            print "Certificate verified and loaded."
            return True
                        
        except Exception,e:
            raise Exception("Certificate format is bad: %s" % e)


if __name__ == "__main__":
    cert = certificate()
    cert.generate('NERV',bits=1024)
    print "-" * 80
    certtext = cert.get_public_text()

    cert2 = certificate()
    cert2.load_public_certificate(certtext)

    cert.save_private_text("testcert")

    cert3 = certificate()
    cert3.load_private_text("testcert")

    certtext2 = cert3.get_public_text()

    print '* ' * 40
    print certtext == certtext2
