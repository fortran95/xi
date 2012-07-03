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
import publickeyalgo,signature,ciphers
from M2Crypto.util import passphrase_callback
from hashes import Hash

def hashable_json(input):
    return json.dumps(input,sort_keys=True,indent=0,ensure_ascii=True).strip()

class certificate(object):
    subject = None
    keys = None
    is_ours = False
    signatures = []
    
    def __init__(self):
        pass
    def generate(self,subject,level=0,**argv):
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
        # clear others
        self.signatures = []
        self.level = level
        
        # After generated, load this cert. into the instance.

    def save_private_text(self,filename,pinreader=passphrase_callback):
        if not self.is_ours:
            raise Exception("Trying to save private info of a public certificate.")

        if os.path.isfile(filename):
            os.remove(filename)
        savesh = shelve.open(filename,writeback=True)
        savesh.clear()

        # save info
        savesh['Title']   = 'Xi_Certificate_Private'
        savesh['Basic']   = self.get_baseinfo()       
        savesh['Signatures'] = []
        # save self.keys
        keyindex = 1
        for k in self.keys:
            keydata = k.get_privatekey(raw=True)
            savesh['Basic']['Public_Key_Ring'][keyindex] = keydata
            keyindex += 1

        # save signatures
        if self.signatures:
            for sig in self.signatures:
                savesh['Signatures'].append(sig)

        # final
        savesh.sync()
        savesh.close()

        """
        if pinreader != None:
            passphrase = pinreader(True)
            key = Hash('sha512',passphrase).digest() + Hash('whirlpool',passphrase).digest()
            print key.encode('base64')
            encryptor = ciphers.xipher(key)
            shcontent = encryptor.encrypt(open(filename,'r').read()).encode('base64')
            os.remove(filename)
            open(filename,'w').write(shcontent)
        """

    def load_private_text(self,filename,pinreader=passphrase_callback):
        #try:
        loadsh = shelve.open(filename)
        """
        except:
            if pinreader != None:
                try:
                    passphrase = pinreader(True)
                    key = Hash('sha512',passphrase).digest() + Hash('whirlpool',passphrase).digest()
                    print key.encode('base64')
                    decryptor = ciphers.xipher(key)
                    shcontent = decryptor.decrypt(open(filename,'r').read().decode('base64'))
                    open(filename + '.temp','w').write(shcontent)
                    loadsh = shelve.open(filename + '.temp')
                except Exception,e:
                    raise Exception("Unable to decrypt given file: %s" % e)
            else:
                raise Exception("Unable to load given file.")
        """

        try:
            if loadsh['Title'] != 'Xi_Certificate_Private':
                raise Exception("Seems not a Xi Project Certificate Private info.")

            # Read subject, version and others

            basic = loadsh['Basic']
            basic_version = basic['Version']
            basic_subject = basic['Subject']
            basic_level   = basic['Level']
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

            self.keys = [eckey, rsakey]
            self.subject = basic_subject
            self.level   = basic_level
            
            # Load signatures
            self.signatures = []
            if loadsh.has_key('Signatures'):
                for sig in loadsh['Signatures']:
                    self.load_signature(sig)

            # Now load this certificate.

            self.is_ours = True

            print "Certificate verified and loaded."
            return True
                        
        except Exception,e:
            raise Exception("Certificate format is bad: %s" % e)


    # XXX 提供使用证书进行加密和签署的方法。用于给证书持有者传递信息，以及让证书持有者自己签署信息。
    # XXX  具体来说，需要提供：
    #    XXX 用自己的私人证书产生给一个来自公共域的证书的签名信息(此人给出信任等级)
    #    XXX 向一个（公有或者私有的）证书中插入来自外人的签名（验证并储存，然后可以通过get_public_text或者save_private_text储存
    
    # XXX  证书如果没有签名，就是可疑的。提供签名和验证签名的方法。
    #        签名信息应当被单独列入一个类，提供签名的产生、导出、验证等方法。验证签名需要相应的公钥证书。
    def do_sign(self,message,raw=True):
        # 通用的签名方法
        if not self.is_ours:
            raise Exception("This is not a private certificate that can be used for signing.")
        ret = {}
        keyindex = 1
        for key in self.keys:
            signer = signature.signature(key.get_privatekey())
            sig = signer.new(message,'SHA1',raw)   # XXX 安全泄漏。应当考虑一种提供选择的方法
            ret[keyindex] = sig
            keyindex += 1
        if raw:
            return ret
        else:
            return json.dumps(ret)

    def verify_sign(self,message,sign):
        try:
            if type(sign) == type(""):
                j = json.loads(sign)
            else:
                j = sign
            keyindex = 1
            for key in self.keys:
                signer = signature.signature(key.get_publickey())
                if j.has_key(keyindex):
                    sig = j[keyindex]
                elif j.has_key(str(keyindex)):
                    sig = j[str(keyindex)]
                else:
                    return False
                if not signer.verify(sig,message):
                    return False
                keyindex += 1
        except Exception,e:
            print "Error: %s" % e
            return False
        return True
        
    def sign_certificate(self,pubcert,trustlevel=0,life=0x9E3400, cert_hashalgo='SHA256', sign_hashalgo='SHA256', raw=False): 
        # 用本证书签署 pubcert， 信任等级默认为0，有效期120天，使用 do_sign 进行最终的签名

        nowtime = time.time() + time.timezone # XXX 注意检查确认为 UTC 时间

        rawinfo = {
            'Title'               : 'New_Signature',
            'Certified_ID'        : pubcert.get_id(),
            'Issuer_ID'           : self.get_id(),
            'Issue_UTC'           : int(nowtime),
            'Valid_To'            : int(nowtime + life),
            'Trust_Level'         : int(trustlevel),
            'Cert_Hash_Algorithm' : cert_hashalgo,
            'Cert_Digest'         : pubcert.get_hash(cert_hashalgo),
            'Sign_Hash_Algorithm' : sign_hashalgo,
        }

        sig = self.do_sign(hashable_json(rawinfo),raw=True)

        ret = {"Content":rawinfo,"Signature":sig}

        # 将签名写入 pubcert
        pubcert.signatures.append(ret)

        if raw:
            return ret
        else:
            return json.dumps(ret)
    def revoke_signature(self,pubcert): # 提供产生对一个公域证书的撤回信息
        pass
    def check_signature_content(self,content,loading=True):
        try:
            if type(content) == type(""):
                c = json.loads(content)
            else:
                c = content
            if   c['Title'] == 'New_Signature':         # 处理新签名的保存等
                testkeys = ('Issuer_ID','Sign_Hash_Algorithm','Certified_ID','Cert_Digest','Trust_Level')

                if int(c['Issue_UTC']) + int(c['Valid_To']) < time.time() + time.timezone:
                    raise Exception("Given signature already expired.")

                if not int(c['Trust_Level']) in range(-3,4):
                    raise Exception("Invalid trust level in the given signature.")

                if loading: # 正在进行的是对一个证书载入新的签名
                    if c['Certified_ID'] != self.get_id():
                        raise Exception("Given signature is not for this certificate.")
                    if c['Cert_Digest'] != self.get_hash(c['Cert_Hash_Algorithm']):
                        raise Exception("Given signature used incorrect digest of this certificate.")
                else:       # 正在进行的是用证书验证某个签名
                    if c['Issuer_ID'] != self.get_id():
                        raise Exception("Given signature cannot be validated with this certificate.")

            elif c['Title'] == 'Revoke_Signature':      # 处理签名撤回
                pass
            else:
                return False
            
            for testkey in testkeys:
                if not c.has_key(testkey):
                    raise Exception("Signature format is bad.")

        except Exception,e:
            print e
            return False
        return True

    def load_signature(self,sign): 
        # 对于私或公用证书均可，加载一个签名信息，可能是签名或签名撤回信息
        # XXX 只能进行初步的形式上的认证：是否是给此证书的，是否过期等。签名的有效性和可信等级需要安全顾问确认，非本class的职责。
        try:
            if type(sign) == type(""):
                j = json.loads(sign)
            else:
                j = sign

            sig = j['Signature']
            c   = j['Content']

            if not self.check_signature_content(c,loading=True):
                raise Exception("This signature cannot be loaded. Either it is of invalid format, or it is not for this certificate.")
            print 'Loaded a signature'
            self.signatures.append(j)
        except Exception,e:
            raise Exception("Error loading a signature: %s" % e)
    def verify_signature(self,sign): # 用本公钥证书验证一个签名
        try:
            if type(sign) == type(""):
                j = json.loads(sign)
            else:
                j = sign
            c = j['Content']
            sig = j['Signature']
    
            if not self.check_signature_content(c,loading=False):
                return False

            return self.verify_sign(hashable_json(c),sig)
        except Exception,e:
            print e
            return False
        return True
    def get_baseinfo(self):
        pubkeyring = {}
        keyindex = 1
        for k in self.keys:
            keydata = k.get_publickey(raw=True)
            pubkeyring[keyindex] = keydata
            keyindex += 1
        baseinfo = {
                'Version': '1',
                'Subject': self.subject,
                'Level'  : int(self.level),
                'Public_Key_Ring':pubkeyring,
            }
        return baseinfo
    def get_id(self):
        return Hash('md5',hashable_json(self.get_baseinfo())).hexdigest()
    def get_hash(self,algo,b64=True):
        if b64:
            digest = Hash(algo,hashable_json(self.get_baseinfo())).digest().encode('base64')
        else:
            digest = Hash(algo,hashable_json(self.get_baseinfo())).hexdigest()
        return digest
    def get_public_text(self):
        # This will generate a publishable certificate text.
        # - subject
        # - pubkeyring
        baseinfo = self.get_baseinfo()        
        # format json.
        hash_source = hashable_json(baseinfo)
        # Get Hashes
        hashes = []
        for algoname in ['SHA512','SHA1','SHA256','MD5','WHIRLPOOL']:
            hashes.append({'Algorithm':algoname,'Hash':self.get_hash(algoname)})
        # Get Signatures
        sigs = []
        if self.signatures:
            for sig in self.signatures:
                sigs.append(sig)
        # Output
        j = {
            'ID'            : self.get_id(),
            'Title'         : 'Xi_Certificate',
            'Basic'         : baseinfo,
            'Finger_Print'  : hashes,
            'Signatures'    : sigs,
            }
        # return
        return json.dumps(j,indent=2,sort_keys=True)
    def load_public_text(self,text):
        try:
            j = json.loads(text)
            if j['Title'] != 'Xi_Certificate':
                raise Exception("Seems not a Xi Project Certificate.")

            # Read subject, version and others

            basic = j['Basic']
            basic_version = basic['Version']
            basic_subject = basic['Subject']
            basic_level   = basic['Level']
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

            # save info
            self.keys = [eckey, rsakey]
            self.subject = basic_subject
            self.level   = basic_level

            # Load signatures
            self.signatures = []
            if j.has_key('Signatures'):
                for sig in j['Signatures']:
                    self.load_signature(sig)

            # Now load this certificate.

            self.is_ours = False

            print "Certificate verified and loaded."
            return True
                        
        except Exception,e:
            raise Exception("Certificate format is bad: %s" % e)

    def _encryptor(self,message,key):
        if len(key) < 128:
            key = Hash('sha512',key).digest() + Hash('whirlpool',key).digest()
        xi = ciphers.xipher(key)
        return xi.encrypt(message)
    def _decryptor(self,message,key):
        if len(key) < 128:
            key = Hash('sha512',key).digest() + Hash('whirlpool',key).digest()
        xi = ciphers.xipher(key)
        return xi.decrypt(message)

    def public_encrypt(self,data,raw=True):
        keyindex = 1
        keyparts = {}
        tempkey = ''
        
        for k in self.keys:
            pka = publickeyalgo.PublicKeyAlgorithm(k.get_publickey())

            # 加密部分密钥
            randomkey = ''
            for i in range(0,64):
                randomkey += chr(random.randint(0,255))
            tempkey += randomkey
            keyparts[keyindex] = json.loads(pka.encrypt(randomkey,self._encryptor))
            

            keyindex += 1
        
        ciphertext = self._encryptor(data,tempkey)
        
        ret = {'Title':'Certificate_Encrypted_Text','Certificate_ID':self.get_id(),'Key_Parts':keyparts,'Ciphertext':ciphertext.encode('base64')}
        if not raw:
            ret = json.dumps(ret)

        return ret
    def private_decrypt(self,data):
        if not self.is_ours:
            raise Exception("This is a public certificate and cannot be used for decrypting.")
        try:
            if type(data) == str:
                j = json.loads(data)
            else:
                j = data
            if j['Title'] != 'Certificate_Encrypted_Text':
                raise Exception("Not a encrypted text.")
            if j['Certificate_ID'] != self.get_id():
                raise Exception("Not for this certificate to decrypt.")
            ciphertext = j['Ciphertext'].decode('base64')
            keyparts   = j['Key_Parts']

            tempkey = ''
            for sqid in keyparts:
                pka = publickeyalgo.PublicKeyAlgorithm(self.keys[sqid - 1].get_privatekey(False))
                randomkey = pka.decrypt(keyparts[sqid],self._decryptor)
                tempkey += randomkey
            print "Tempkey is: %s" % tempkey
        except Exception,e:
            raise Exception("Decrypting Failure: %s" % e)
if __name__ == "__main__":
    c = certificate()
    c.generate('ALICE',level=9,bits=1024)
#    c.save_private_text('alice.private')

#    d = certificate()
#    d.load_private_text('alice.private')
    ped = c.public_encrypt('a' * 1025,True)
    print c.private_decrypt(ped)
