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
import random,time,os
from M2Crypto import EC,RSA
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
        
        print "Generated new EC key basing on %s." % curve_name
    def _derive_pubkey(self):
        # derive EC public key instance from self._key
        if self._key == None:
            return False
        filename = 'temp' + str(int(random.random()))
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
    exit()
    from M2Crypto import EC
    import os,base64
    eckey1 = EC.gen_params(EC.NID_sect571r1)
    eckey2 = EC.gen_params(EC.NID_sect571r1)
    
    eckey1.gen_key()
    eckey2.gen_key()
    
    eckey1.save_pub_key('temp1')
    eckey2.save_pub_key('temp2')
    
    eckey1pub = EC.load_pub_key('temp1')
    eckey2pub = EC.load_pub_key('temp2')
    
    exit()
    
    ss1 = eckey1.compute_dh_key(eckey2pub)
    ss2 = eckey2.compute_dh_key(eckey1pub)
    
    #print base64.encodestring(ss1)
    #print base64.encodestring(ss2)
    
    msgdigest = '000'
    signature = eckey1.sign_dsa_asn1(msgdigest).encode('hex') # Sign Using a key derived from Private Parameters
    print "The signature is: %s" % signature
    print "Length of signature is: %d" % len(signature)
    
    print "Now verify."
    print eckey1pub.verify_dsa_asn1(msgdigest,signature.decode('hex'))
    
    os.remove('temp1')
    os.remove('temp2')