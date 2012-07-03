# -*- coding: utf-8 -*-

import random,time,os,json,uuid,hashlib,math
from M2Crypto import EC,RSA
def tempfilename():
    return hashlib.md5(str(uuid.uuid3(uuid.uuid1(),str(uuid.uuid4())))).hexdigest()

class PublicKeyAlgorithm(object):
    # Generic Loader of Public Keys.
    is_private_key = None

    def __init__(self,keystr):
        try:
            if type(keystr) == str:
                j = json.loads(keystr)
            else:
                j = keystr

            if j['type'] == 'RSA_Public_Key':
                self.key = _RSA()
                self.is_private_key = False
            elif j['type'] == 'EC_Public_Key':
                self.key = _EC()
                self.is_private_key = False
            elif j['type'] == 'RSA_Private_Key':
                self.key = _RSA()
                self.is_private_key = True
            elif j['type'] == 'EC_Private_Key':
                self.key = _EC()
                self.is_private_key = True
            else:
                raise Exception("Unrecognized type of public key.")
            
            keystr = json.dumps(j)

            if self.is_private_key:
                self.key.load_privatekey(keystr)
            else:
                self.key.load_publickey(keystr)
        except Exception,e:
            raise Exception("Failed initilizing PublicKeyAlgorithm: %s" % e)

    def get_publickey(self,raw=False):
        return self.key.get_publickey(raw)

    def get_privatekey(self,raw=False):
        return self.key.get_privatekey(raw)

    def sign(self,digest):
        return self.key.sign(digest)

    def verify(self,digest,sign):
        return self.key.verify(digest,sign)

    def encrypt(self,message,encryptor):
        return self.key.encrypt(message,encryptor)

    def decrypt(self,ciphertext,decryptor):
        return self.key.decrypt(ciphertext,decryptor)

class _RSA(object):
    _key = None
    _pubkey = None
    def __init__(self):
        pass
    def sign_limit(self):    # 返回支持加密的文本长度
        return int(self.bits * 0.75 / 8)
    def generate(self,**argv):
        if argv.has_key('bits'):
            bits = argv['bits']
        else:
            bits = 4096
        if bits < 1024:
            raise Exception("Cannot accept such bits < 1024.")
        self.bits = bits
        print "Generating a %d bits RSA key, please wait." % bits
        self._key = RSA.gen_key(bits,65537)
        print "RSA key generation done."
        self._derive_pubkey()
    def sign(self,digest):
        if self._key == None:
            return False
        encrypted = self._key.private_encrypt(digest,1)
        return encrypted
    def verify(self,digest,sign):
        if self._pubkey == None:
            return False
        try:
            decrypted = self._pubkey.public_decrypt(sign,1)
            if decrypted == digest:
                return True
        except Exception,e:
            pass
        return False
    def encrypt(self,message,encryptor):
        if self._pubkey == None:
            return False
        # Generate a temp key and encrypt it using RSA.
        tempkey = ''
        maxlen = int(self.bits * 0.5 / 8)
        for i in range(0,maxlen):
            tempkey += chr(random.randint(0,255))
        # encrypt the message using tempkey.
        data = encryptor(message,tempkey)
        keyinfo = self._pubkey.public_encrypt(tempkey,4)
        # Write out.
        ret = {
               'type':'RSA_Encrypted',
               'tkey':keyinfo.encode('base64'),
               'ciphertext':data.encode('base64'),
            }
        return json.dumps(ret,indent=4)
    def decrypt(self,ciphertext,decryptor):
        if self._key == None:
            return False
        try:
            if type(ciphertext) == str:
                j = json.loads(ciphertext)
            else:
                j = ciphertext
            if j['type'] != 'RSA_Encrypted':
                raise Exception("Input may not be the intending ciphertext.")
            tempkey = j['tkey'].decode('base64')
            ciphertext= j['ciphertext'].decode('base64')
        except:
            raise Exception("Bad RSA ciphertext format.")
        try:
            tempkey = self._key.private_decrypt(tempkey,4)
        except Exception,e:
            raise Exception("Unable to decrypt this RSA ciphertext: %s" % e)
        return decryptor(ciphertext,tempkey)
    def load_publickey(self,publickey):
        # Try parse the public key info.
        try:
            j = json.loads(publickey)
            if j['type'] != 'RSA_Public_Key':
                raise Exception("This is not a public key thus cannot be loaded.")
            pkdata = j['data'].decode('base64')
            self.bits = int(j['bits'])
        except Exception,e:
            raise Exception("Failed loading publickey. Bad format. Error: %s" % e)
        # If parsable, Write down and load.
        try:
            filename = tempfilename()
            open(filename,'w+').write(pkdata)
            self._pubkey = RSA.load_pub_key(filename)
            os.remove(filename)
        except Exception,e:
            raise Exception("Cannot load public key.")
        # Delete existing private key to avoid conflicts.
        self._key = None
        # succeeded.
        return True
    def load_privatekey(self,privatekey):
        # Try parse the private key info.
        try:
            j = json.loads(privatekey)
            if j['type'] != 'RSA_Private_Key':
                raise Exception("This is not a private key thus cannot be loaded.")
            pkdata = j['data'].decode('base64')
            self.bits = int(j['bits'])
        except Exception,e:
            raise Exception("Failed loading privatekey. Bad format.")
        # If parsable, Write down and load.
        try:
            filename = tempfilename()
            open(filename,'w+').write(pkdata)
            self._key = RSA.load_key(filename)
            os.remove(filename)
        except Exception,e:
            raise Exception("Cannot load private key. Error: %s" % e)
        # Override existing public key.
        self._derive_pubkey()
        # succeeded.
        return True
    def get_publickey(self,raw=False):
        if self._pubkey == None:
            return False
        # Retrive pubkey data
        filename = tempfilename()
        self._pubkey.save_pub_key(filename)
        pubkeydata = open(filename).read()
        os.remove(filename)
        # Write down a good form of public key.
        pkinfo = {
                'type'  :'RSA_Public_Key',
                'bits'  :self.bits,
                'data'  :pubkeydata.encode('base64')
            }
        if raw:
            return pkinfo
        return json.dumps(pkinfo,indent=4)
    def get_privatekey(self,raw=False):
        if self._key == None:
            return False
        # Retrive privatekey data
        filename = tempfilename()
        self._key.save_key(filename,None)
        prvkeydata = open(filename).read()
        os.remove(filename)
        # Write down a good form of public key.
        pkinfo = {
                'type'  :'RSA_Private_Key',
                'bits'  :self.bits,
                'data'  :prvkeydata.encode('base64')
            }
        if raw:
            return pkinfo
        return json.dumps(pkinfo,indent=4)
    def _derive_pubkey(self):
        # derive EC public key instance from self._key
        if self._key == None:
            return False
        filename = tempfilename()
        self._key.save_pub_key(filename)
        self._pubkey = RSA.load_pub_key(filename)
        os.remove(filename)
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
    def sign_limit(self):
        if self._key != None:
            curvename = self._key_curve
        elif self._pubkey != None:
            curvename = self._pubkey_curve
        else:
            raise Exception("Not initilized.")

        curvename = self._curves_name[curvename]
        # XXX XXX XXX XXX XXX XXX 这里没有完善！XXX XXX XXX XXX XXX XXX XXX
        if curvename[0:10] == 'NID_X9_62_':
            return int(math.floor(int(curvename[15:18]) / 8.0))
        elif curvename[0:7] == 'NID_sec':
            return int(math.floor(int(curvename[8:11] ) / 8.0))
        else:
            return 10

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
        
        # XXX TODO REMOVE THIS
        print "Length of key is: %d" % (len(sharedsecret) * 8)

        # Encrypt
        ciphertext = encryptor(message,sharedsecret)
        # Get tempkey's public key.
        filename = tempfilename()
        tempkey.save_pub_key(filename)
        publickey = open(filename).read()
        os.remove(filename)
        # Return with json.
        ret = json.dumps(
            {
                'type':'EC_Encrypted',
                'public_key':publickey.encode('base64'),
                'ciphertext':ciphertext.encode('base64'),
            }
        )
        return ret
    def decrypt(self,ciphertext,decryptor):
        if self._key == None:
            return False
        try:
            if type(ciphertext) == str:
                j = json.loads(ciphertext)
            else:
                j = ciphertext
            if j['type'] != 'EC_Encrypted':
                raise Exception("Input may not be the intending ciphertext.")
            publickey = j['public_key'].decode('base64')
            ciphertext= j['ciphertext'].decode('base64')
        except Exception,e:
            raise Exception("Bad EC ciphertext format.")
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
    def get_publickey(self,raw=False):
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
        if raw:
            return pkinfo
        return json.dumps(pkinfo,indent=4)
    def get_privatekey(self,raw=False):
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
        if raw:
            return pkinfo
        return json.dumps(pkinfo,indent=4)
    def _derive_pubkey(self):
        # derive EC public key instance from self._key
        if self._key == None:
            return False
        filename = tempfilename()
        self._key.save_pub_key(filename)
        self._pubkey = EC.load_pub_key(filename)
        os.remove(filename)

if __name__ == "__main__":
    r = _EC()
    r.generate()
    def encryptor(key,message):
        return 'ok'
    r.encrypt('a' * 1024, encryptor)
    print "Sign limit: %d" % (r.sign_limit() * 8)
    r.sign('a' * r.sign_limit())
