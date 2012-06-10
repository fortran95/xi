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
from M2Crypto import EC,RSA
def tempfilename():
    return hashlib.md5(str(uuid.uuid3(uuid.uuid1(),str(uuid.uuid4())))).hexdigest()
class _RSA(object):
    def __init__(self):
        pass
    def generate(self,**argv):
        pass
    def sign(self,digest):
        pass
    def verify(self,digest,sign):
        pass
    def encrypt(self,message,encryptor):
        pass
    def decrypt(self,ciphertext,decryptor):
        pass
    def load_publickey(self,publickey):
        pass
    def load_privatekey(self,privatekey):
        pass
    def get_publickey(self):
        pass
    def get_privatekey(self):
        pass
class _EC(object):
    _curves_name = {
        707:'NID_secp128r2',
        706:'NID_secp128r1',
        728:'NID_sect239k1',
        704:'NID_secp112r1',
        705:'NID_secp112r2',
        687:'NID_X9_62_c2pnb176v1',
        730:'NID_sect283r1',
        699:'NID_X9_62_c2pnb272w1',
        689:'NID_X9_62_c2tnb191v2',
        708:'NID_secp160k1',
        741:'NID_wap_wsg_idm_ecid_wtls8',
        716:'NID_secp521r1',
        736:'NID_wap_wsg_idm_ecid_wtls3',
        735:'NID_wap_wsg_idm_ecid_wtls1',
        739:'NID_wap_wsg_idm_ecid_wtls6',
        740:'NID_wap_wsg_idm_ecid_wtls7',
        703:'NID_X9_62_c2tnb431r1',
        727:'NID_sect233r1',
        721:'NID_sect163k1',
        738:'NID_wap_wsg_idm_ecid_wtls5',
        714:'NID_secp256k1',
        688:'NID_X9_62_c2tnb191v1',
        712:'NID_secp224k1',
        412:'NID_X9_62_prime239v1',
        413:'NID_X9_62_prime239v2',
        414:'NID_X9_62_prime239v3',
        737:'NID_wap_wsg_idm_ecid_wtls4',
        702:'NID_X9_62_c2pnb368w1',
        742:'NID_wap_wsg_idm_ecid_wtls9',
        731:'NID_sect409k1',
        685:'NID_X9_62_c2pnb163v2',
        710:'NID_secp160r2',
        709:'NID_secp160r1',
        684:'NID_X9_62_c2pnb163v1',
        693:'NID_X9_62_c2pnb208w1',
        722:'NID_sect163r1',
        723:'NID_sect163r2',
        700:'NID_X9_62_c2pnb304w1',
        719:'NID_sect131r1',
        720:'NID_sect131r2',
        715:'NID_secp384r1',
        732:'NID_sect409r1',
        411:'NID_X9_62_prime192v3',
        690:'NID_X9_62_c2tnb191v3',
        409:'NID_X9_62_prime192v1',
        694:'NID_X9_62_c2tnb239v1',
        695:'NID_X9_62_c2tnb239v2',
        696:'NID_X9_62_c2tnb239v3',
        724:'NID_sect193r1',
        725:'NID_sect193r2',
        701:'NID_X9_62_c2tnb359v1',
        726:'NID_sect233k1',
        717:'NID_sect113r1',
        718:'NID_sect113r2',
        743:'NID_wap_wsg_idm_ecid_wtls10',
        744:'NID_wap_wsg_idm_ecid_wtls11',
        745:'NID_wap_wsg_idm_ecid_wtls12',
        686:'NID_X9_62_c2pnb163v3',
        729:'NID_sect283k1',
        733:'NID_sect571k1',
        415:'NID_X9_62_prime256v1',
        410:'NID_X9_62_prime192v2',
        711:'NID_secp192k1',
        734:'NID_sect571r1',
        713:'NID_secp224r1',
        }
    _curves_id = {
        'NID_secp112r1':704,
        'NID_secp112r2':705,
        'NID_secp128r1':706,
        'NID_secp128r2':707,
        'NID_secp160k1':708,
        'NID_secp160r1':709,
        'NID_secp160r2':710,
        'NID_secp192k1':711,
        'NID_secp224k1':712,
        'NID_secp224r1':713,
        'NID_secp256k1':714,
        'NID_secp384r1':715,
        'NID_secp521r1':716,
        'NID_sect113r1':717,
        'NID_sect113r2':718,
        'NID_sect131r1':719,
        'NID_sect131r2':720,
        'NID_sect163k1':721,
        'NID_sect163r1':722,
        'NID_sect163r2':723,
        'NID_sect193r1':724,
        'NID_sect193r2':725,
        'NID_sect233k1':726,
        'NID_sect233r1':727,
        'NID_sect239k1':728,
        'NID_sect283k1':729,
        'NID_sect283r1':730,
        'NID_sect409k1':731,
        'NID_sect409r1':732,
        'NID_sect571k1':733,
        'NID_sect571r1':734,
        'NID_X9_62_prime192v1':409,
        'NID_X9_62_prime192v2':410,
        'NID_X9_62_prime192v3':411,
        'NID_X9_62_prime239v1':412,
        'NID_X9_62_prime239v2':413,
        'NID_X9_62_prime239v3':414,
        'NID_X9_62_prime256v1':415,
        'NID_X9_62_c2pnb163v1':684,
        'NID_X9_62_c2pnb163v2':685,
        'NID_X9_62_c2pnb163v3':686,
        'NID_X9_62_c2pnb176v1':687,
        'NID_X9_62_c2tnb191v1':688,
        'NID_X9_62_c2tnb191v2':689,
        'NID_X9_62_c2tnb191v3':690,
        'NID_X9_62_c2pnb208w1':693,
        'NID_X9_62_c2tnb239v1':694,
        'NID_X9_62_c2tnb239v2':695,
        'NID_X9_62_c2tnb239v3':696,
        'NID_X9_62_c2pnb272w1':699,
        'NID_X9_62_c2pnb304w1':700,
        'NID_X9_62_c2tnb359v1':701,
        'NID_X9_62_c2pnb368w1':702,
        'NID_X9_62_c2tnb431r1':703,
        'NID_wap_wsg_idm_ecid_wtls1':735,
        'NID_wap_wsg_idm_ecid_wtls3':736,
        'NID_wap_wsg_idm_ecid_wtls4':737,
        'NID_wap_wsg_idm_ecid_wtls5':738,
        'NID_wap_wsg_idm_ecid_wtls6':739,
        'NID_wap_wsg_idm_ecid_wtls7':740,
        'NID_wap_wsg_idm_ecid_wtls8':741,
        'NID_wap_wsg_idm_ecid_wtls9':742,
        'NID_wap_wsg_idm_ecid_wtls10':743,
        'NID_wap_wsg_idm_ecid_wtls11':744,
        'NID_wap_wsg_idm_ecid_wtls12':745,
    }
    _key = None
    _pubkey = None
    _key_curve = None
    _pubkey_curve = None
    def __init__(self):
        pass
    def generate(self,**argv):
        # select EC curve.
        if argv.has_key('curve'):
            curve = argv['curve']
        else:
            curve = random.choice(self._curves_id.items())
            curve = curve[1]
        if not self._curves_name.has_key(curve):
            raise Exception("User desired impractical EC parameter.")
        curve_name = self._curves_name[curve]
        # generate a new EC instance, init both secret and public key instance.
        self._key = EC.gen_params(curve)
        self._key.gen_key()
        self._derive_pubkey()
        self._key_curve, self._pubkey_curve = curve,curve
        
        print "Generated new EC key basing on %s." % curve_name
    def sign(self,digest):
        # sign the given DIGEST. Output was base64-encoded.
        if self._key == None:
            return False
        return self._key.sign_dsa_asn1(digest).encode('base64')
    def verify(self,digest,sign):
        # verify the DIGEST with given SIGN.
        if self._pubkey == None:
            return False
        try:
            sign = sign.decode('base64') # in sign we set output being base64-encoded.
            if self._pubkey.verify_dsa_asn1(digest,sign):
                return True
        except Exception,e:
            print "Failed verifying signature: %s" % e
        return False
    def encrypt(self,message,encryptor):
        if self._pubkey == None or self._pubkey_curve == None: # To send message via PublicKey, We must know it's curve.
            return False
        # Get a temp. key
        tempkey = EC.gen_params(self._pubkey_curve)
        tempkey.gen_key()
        sharedsecret = tempkey.compute_dh_key(self._pubkey)
        # Encrypt
        ciphertext = encryptor(message,sharedsecret)
        # Get tempkey's public key.
        filename = tempfilename()
        tempkey.save_pub_key(filename)
        publickey = open(filename).read()
        os.remove(filename)
        # Return with json.
        publickey = publickey.encode('base64')
        ret = json.dumps(
            {
                'type':'EC_Encrypted',
                'public_key':publickey,
                'ciphertext':ciphertext,
            }
        )
        return ret
    def decrypt(self,ciphertext,decryptor):
        if self._key == None:
            return False
        try:
            j = json.loads(ciphertext)
            if j['type'] != 'EC_Encrypted':
                raise Exception("Input may not be the intending ciphertext.")
            publickey = j['public_key'].decode('base64')
            ciphertext= j['ciphertext']
        except:
            raise Exception("Bad ciphertext format.")
        try:
            # Read the temp. key. First write to a file.
            filename = tempfilename()
            open(filename,'w+').write(publickey)
            tempkey = EC.load_pub_key(filename)
            os.remove(filename)
            # Combine this temp. key with our private key, and get Shared Secret.
            sharedsecret = self._key.compute_dh_key(tempkey)
        except Exception,e:
            raise Exception("Unable to load public key. Error is [%s]." % e)
        return decryptor(ciphertext,sharedsecret)
    def load_publickey(self,publickey):
        # Try parse the public key info.
        try:
            j = json.loads(publickey)
            if j['type'] != 'EC_Public_Key':
                raise Exception("This is not a public key thus cannot be loaded.")
            if self._curves_id.has_key(j['curve']):
                curve = self._curves_id[j['curve']]
            else:
                raise Exception("Unrecognized EC curve specified.")
            pkdata = j['data'].decode('base64')
        except Exception,e:
            raise Exception("Failed loading publickey. Bad format. Error: %s" % e)
        # If parsable, Write down and load.
        try:
            filename = tempfilename()
            open(filename,'w+').write(pkdata)
            self._pubkey = EC.load_pub_key(filename)
            self._pubkey_curve = curve
            os.remove(filename)
        except Exception,e:
            raise Exception("Cannot load public key.")
        # Delete existing private key to avoid conflicts.
        self._key = None
        self._key_curve = None
        # succeeded.
        return True
    def load_privatekey(self,privatekey):
        # Try parse the private key info.
        try:
            j = json.loads(privatekey)
            if j['type'] != 'EC_Private_Key':
                raise Exception("This is not a private key thus cannot be loaded.")
            if self._curves_id.has_key(j['curve']):
                curve = self._curves_id[j['curve']]
            else:
                raise Exception("Unrecognized EC curve specified.")
            pkdata = j['data'].decode('base64')
        except Exception,e:
            raise Exception("Failed loading privatekey. Bad format.")
        # If parsable, Write down and load.
        try:
            filename = tempfilename()
            open(filename,'w+').write(pkdata)
            self._key = EC.load_key(filename)
            self._key_curve = curve
            os.remove(filename)
        except Exception,e:
            raise Exception("Cannot load private key. Error: %s" % e)
        # Override existing public key.
        self._pubkey_curve = curve
        self._derive_pubkey()
        # succeeded.
        return True
    def get_publickey(self):
        if self._pubkey == None or self._pubkey_curve == None:
            return False
        # Retrive pubkey data
        filename = tempfilename()
        self._pubkey.save_pub_key(filename)
        pubkeydata = open(filename).read()
        os.remove(filename)
        # Write down a good form of public key.
        pkinfo = {
                'type'  :'EC_Public_Key',
                'curve' :self._curves_name[self._pubkey_curve],
                'data'  :pubkeydata.encode('base64')
            }
        return json.dumps(pkinfo,indent=4)
    def get_privatekey(self):
        if self._key == None or self._key_curve == None:
            return False
        # Retrive privatekey data
        filename = tempfilename()
        self._key.save_key(filename,None)
        prvkeydata = open(filename).read()
        os.remove(filename)
        # Write down a good form of public key.
        pkinfo = {
                'type'  :'EC_Private_Key',
                'curve' :self._curves_name[self._key_curve],
                'data'  :prvkeydata.encode('base64')
            }
        return json.dumps(pkinfo,indent=4)
    def _derive_pubkey(self):
        # derive EC public key instance from self._key
        if self._key == None:
            return False
        filename = tempfilename()
        self._key.save_pub_key(filename)
        self._pubkey = EC.load_pub_key(filename)
        os.remove(filename)
class certificate(object):
    def __init__():
        pass
    def generate(**argv):
        # Will generate a new certificate. Compatiable to NERV-XI-001 Standard.
        
        # - subject
        # - 
        pass
    
if __name__ == "__main__":
    ec = _EC()
    ec.generate()
    def encryptor(message,key):
        print "[%s] encrypted using key [%s](%d bits)." % (message,key.encode('hex'),len(key) * 8)
        return message.encode('hex')
    def decryptor(message,key):
        print "[%s] decrypted using key [%s]." % (message,key.encode('hex'))
        return message.decode('hex')
    #cp = ec.encrypt('message',encryptor)
    eck = ec.get_privatekey()
    
    ec1 = _EC()
    ec1.load_privatekey(eck)
    
    pk = ec1.get_publickey()
    
    ec2 = _EC()
    ec2.load_publickey(pk)
    
    encrypted = ec2.encrypt('message, here.',encryptor)
    decrypted = ec1.decrypt(encrypted,decryptor)
    
    print decrypted
    