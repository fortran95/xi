# -*- coding: utf-8 -*-

import random
import time
import os
import uuid
import shelve
import logging
import json

from M2Crypto.util import passphrase_callback
import bson as serializer

import publickeyalgo
import signature
import ciphers
from hashes import Hash

log = logging.getLogger('xi.ceritificate')

def hashable_obj(input):
    return json.dumps(input,sort_keys=True,indent=0,ensure_ascii=True).strip()

class certificate(object):
    subject = None
    keys = None
    is_ours = False
    private_save_key = None
    signatures = []
    #sign_revoke_list = [] # Records which issuers have revoked their signatures.
    
    def __init__(self):
        pass
    def _validate_subject(self,subj):
        if type(subj) != str:
            return False
        if len(subj) > 128 or len(subj) < 3:
            return False
        for c in subj:
            if c not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_ .":
                return False
        return True 
    def derive_savekey(self,passphrase):
        return Hash('sha512',passphrase).digest() + Hash('whirlpool',passphrase).digest()

    def generate(self,subject,level=0,**argv):
        # Will generate a new certificate. Compatiable with NERV-XI-001 Standard.

        log.info("Now generating new Xi certificate: Subject[%s] Level[%s].",subject,level)

        # - subject
        subject = subject.strip()
        if not self._validate_subject(subject):

            log.exception("Required certificate subject's invalid.")

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
        self.private_save_key = None
        
        # After generated, load this cert. into the instance.

        log.info("New Xi certificate generation done.")

    def save_private_text(self,filename,pinreader=passphrase_callback):
        if not self.is_ours:
            log.exception("Attempt to save a public certificate's private info failed.")
            raise Exception("Trying to save private info of a public certificate.")

        if os.path.isfile(filename):
            os.remove(filename)
        savesh = {}

        # save info
        savesh['Title']   = 'Xi_Certificate_Private'
        savesh['Basic']   = self.get_baseinfo()       
        savesh['Signatures'] = []
        # save self.keys
        keyindex = 1
        for k in self.keys:
            keydata = k.get_privatekey(raw=True)
            savesh['Basic']['Public_Key_Ring'][str(keyindex)] = keydata
            keyindex += 1

        # save signatures
        if self.signatures:
            for sig in self.signatures:
                savesh['Signatures'].append(sig)

        # final
#        open(filename,'w+').write(savesh)
        shcontent = serializer.dumps(savesh)
        
        if pinreader != None:
            if self.private_save_key == None:
                passphrase = pinreader(True)
                key = self.derive_savekey(passphrase)
                self.private_save_key = key
            else:
                key = self.private_save_key
            #print key.encode('base64')
            encryptor = ciphers.xipher(key)
            shcontent = encryptor.encrypt(shcontent)

        open(filename,'w').write(shcontent)
        
        log.info("Successfully saved private info.")
    def load_private_text(self,filename,pinreader=passphrase_callback):

        log.info("Trying to load a private certificate.")

        try:
            loadsh = serializer.loads(open(filename,'r').read())
            log.info("Load as plain text with no passphrase seems OK.")

        except:
            if pinreader != None:
                try:

                    log.info("Load as encrypted text. Requiring passphrase.")

                    passphrase = pinreader(False)
                    if type(passphrase) != str:
                        raise Exception("User refused passphrase request.")
                    key = self.derive_savekey(passphrase)
                    self.private_save_key = key

                    decryptor = ciphers.xipher(key)
                    shcontent = decryptor.decrypt(open(filename,'r').read())
                    
                    loadsh = serializer.loads(shcontent)
                except Exception,e:
                    log.exception("Unable to decrypt given file: %s",e)
                    raise Exception("Unable to decrypt given file: %s" % e)
            else:
                raise Exception("Unable to load given file.")

        try:
            if loadsh['Title'] != 'Xi_Certificate_Private':
                raise Exception("Seems not a Xi Project Certificate Private info.")

            # Read subject, version and others

            basic = loadsh['Basic']
            basic_version = basic['Version']
            basic_subject = basic['Subject']
            basic_level   = basic['Level']
            basic_public_key_ring = basic['Public_Key_Ring']

            certid = Hash('md5',hashable_obj(basic)).hexdigest()

            # Try to load public keys

            basic_prvkey_sensible = True
            eckey = publickeyalgo._EC()
            rsakey = publickeyalgo._RSA()
            try:
                for key in basic_public_key_ring:

                    prvkey = basic_public_key_ring[key]
                    if prvkey['type'] == 'EC_Private_Key':
                        ret = eckey.load_privatekey(serializer.dumps(prvkey))
                    elif prvkey['type'] == 'RSA_Private_Key':
                        ret = rsakey.load_privatekey(serializer.dumps(prvkey))
                    basic_prvkey_sensible = basic_prvkey_sensible and ret

            except Exception,e:
                print "Error occured: %s" % e
                basic_prvkey_sensible = False
            if not basic_prvkey_sensible:
                raise Exception("This ceritificate's private key info is non-sense.")
            if not ( eckey._key != None and rsakey._key != None ):
#                print (eckey._key != None, rsakey._key != None)
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

            log.info("Private certificate verified and loaded. Subject[%s].",basic_subject)
                        
        except Exception,e:
            
            log.exception("Cannot load private certificate: %s",e)

            raise Exception("Certificate format is bad: %s" % e)
            return False

        return True

    def do_sign(self,message,raw=True):
        # 通用的签名方法
        if not self.is_ours:
            raise Exception("This is not a private certificate that can be used for signing.")
        ret = {}
        keyindex = 1
        for key in self.keys:
            signer = signature.signature(key.get_privatekey())
            signlimit = key.sign_limit()

            hashalgo = Hash().consult(signlimit)
            if len(hashalgo) < 1:
                raise Exception("No suitable hash functions found.")
            maxhash = hashalgo[max(hashalgo.keys())]
            choosenalgo = maxhash[random.randint(0,len(maxhash) - 1)]

            sig = signer.new(message,choosenalgo,raw)   # XXX 安全泄漏。应当考虑一种提供选择的方法
            ret[str(keyindex)] = sig
            keyindex += 1
        if raw:
            return ret
        else:
            return serializer.dumps(ret)

        log.info("Successfully made a sign.")

    def verify_sign(self,message,sign):
        try:
            if type(sign) == type(""):
                j = serializer.loads(sign)
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

            log.warning("Failed verifying a sign, returning False. More details: %s",e)

            print "Error: %s" % e
            return False
        return True
        
    def sign_certificate(self,pubcert,trustlevel=0,life=0x9E3400, cert_hashalgo='whirlpool', raw=False):
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
        }

        log.info('Signing Certificate: Subject[%s] TrustLevel[%s] ValidTo[%s]',rawinfo['Certified_ID'],rawinfo['Trust_Level'],rawinfo['Valid_To'])

        sig = self.do_sign(hashable_obj(rawinfo),raw=True)

        ret = {"Content":rawinfo,"Signature":sig}

        # 将签名写入 pubcert
        pubcert.signatures.append(ret)

        if raw:
            return ret
        else:
            return serializer.dumps(ret)
    def revoke_signature(self,pubcert, raw=False): # 提供产生对一个公域证书的撤回信息
        nowtime = time.time() + time.timezone
        rawinfo = {
            'Title'                 : 'Revoke_Signature',
            'Target_ID'             : pubcert.get_id(),
            'Issuer_ID'             : self.get_id(),
            'Issue_UTC'             : int(nowtime),
        }
        sig = self.do_sign(hashable_obj(rawinfo),raw=True)
        ret = {"Content":rawinfo,"Signature":sig}
        
        pubcert.signatures.append(ret)

        if raw:
            return ret
        else:
            return serializer.dumps(ret)
        
    def check_signature_content(self,content,loading=True):
        nowtime = time.time() + time.timezone
        try:
            if type(content) == type(""):
                c = serializer.loads(content)
            else:
                c = content
            if   c['Title'] == 'New_Signature':         # 处理新签名的保存等
                testkeys = ('Issuer_ID','Certified_ID','Cert_Digest','Trust_Level')

                if int(c['Issue_UTC']) + int(c['Valid_To']) < nowtime:
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
                testkeys = ('Issuer_ID','Target_ID')
                if int(c['Issue_UTC']) > nowtime or int(c['Issue_UTC']) < 0:
                    raise Exception("Given revocation time invalid.")
                if loading:
                    if c['Target_ID'] != self.get_id():
                        raise Exception("Given signature is not for this certificate.")
                else:
                    if c['Issuer_ID'] != self.get_id():
                        raise Exception("Given signature cannot be validated with this certificate.")
            else:
                return False
            
            for testkey in testkeys:
                if not c.has_key(testkey):
                    raise Exception("Signature format is bad.")

        except Exception,e:
            log.warning('Signature content check cannot pass. Details: %s',e)
            return False
        return True

    def signature_hash(self,sign):
        try:
            if type(sign) == type(""):
                j = serializer.loads(sign)
            else:
                j = sign
            jc = j['Content']
            p1 = jc['Certified_ID'].strip().lower()
            p2 = jc['Issuer_ID'].strip().lower()
            p3 = int(jc['Issue_UTC'])
            p4 = int(jc['Valid_To'])
            p5 = int(jc['Trust_Level'])
            return "%s;%s;%d;%d;%d" % (p1,p2,p3,p4,p5)
        except Exception,e:
            return False

    def load_signature(self,sign): 
        # 对于私或公用证书均可，加载一个签名信息，可能是签名或签名撤回信息
        try:
            if type(sign) == type(""):
                j = serializer.loads(sign)
            else:
                j = sign

            sig   = j['Signature']
            c     = j['Content']
            chash = self.signature_hash(j)

            if not self.check_signature_content(c,loading=True):
                raise Exception("This signature cannot be loaded. Either it is of invalid format, or it is not for this certificate.")
            log.info('Signature loaded.')

            for s in self.signatures:
                if self.signature_hash(s) == chash:
                    log.warning('This signature has already been loaded.')
                    return

            self.signatures.append(j)
        except Exception,e:

            log.warning('Cannot load the signature. Details: %s',e)

            raise Exception("Error loading a signature: %s" % e)
    def verify_signature(self,sign): # 用本公钥证书验证一个签名
        try:
            if type(sign) == type(""):
                j = serializer.loads(sign)
            else:
                j = sign
            c = j['Content']
            sig = j['Signature']
    
            if not self.check_signature_content(c,loading=False):
                return False

            return self.verify_sign(hashable_obj(c),sig)
        except Exception,e:
            
            log.warning('Signature being invalid. Returning False. Details: %s',e)

            return False
        return True
    def get_baseinfo(self):
        pubkeyring = {}
        keyindex = 1
        for k in self.keys:
            keydata = k.get_publickey(raw=True)
            pubkeyring[str(keyindex)] = keydata
            keyindex += 1
        baseinfo = {
                'Version': '1',
                'Subject': self.subject,
                'Level'  : int(self.level),
                'Public_Key_Ring':pubkeyring,
            }
        return baseinfo
    def get_id(self):
        return Hash('md5',hashable_obj(self.get_baseinfo())).hexdigest()
    def get_hash(self,algo,b64=True):
        if b64:
            digest = Hash(algo,hashable_obj(self.get_baseinfo())).digest().encode('base64')
        else:
            digest = Hash(algo,hashable_obj(self.get_baseinfo())).hexdigest()
        return digest
    def get_public_text(self):
        # This will generate a publishable certificate text.
        # - subject
        # - pubkeyring
        baseinfo = self.get_baseinfo()        
        # format serializer.
        hash_source = hashable_obj(baseinfo)
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
        return serializer.dumps(j)
    def load_public_text(self,text):
        try:
            j = serializer.loads(text)
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
                        ret = eckey.load_publickey(serializer.dumps(pubkey))
                    elif pubkey['type'] == 'RSA_Public_Key':
                        ret = rsakey.load_publickey(serializer.dumps(pubkey))
                    basic_pubkey_sensible = basic_pubkey_sensible and ret
            except Exception,e:
                print "Error occured: %s" % e
                basic_pubkey_sensible = False
            if not basic_pubkey_sensible:
                raise Exception("This ceritificate's public key info is non-sense.")
            if not ( eckey._pubkey != None and rsakey._pubkey != None ):
                raise Exception("This certificate has insufficient public key info.")

            # Verify Integrity

            hash_source = hashable_obj(basic)
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
            self.private_save_key = None

            log.info('Public certificate successfully loaded. Subject[%s].',basic_subject)

            return True
                        
        except Exception,e:
            
            log.exception('Cannot load certificate: %s',e)

            raise Exception("Certificate format is bad: %s" % e)

    def _encryptor(self,key,message):
#        print key.encode('hex')
        if len(key) < 128:
            key = Hash('sha512',key).digest() + Hash('whirlpool',key).digest()
       
#        print "encrypt with: %s" % Hash('md5',key).hexdigest()

        xi = ciphers.xipher(key)

        ctext = xi.encrypt(message)
        return ctext
    def _decryptor(self,key,ciphertext):
#        print key.encode('hex')
        if len(key) < 128:
            key = Hash('sha512',key).digest() + Hash('whirlpool',key).digest()
        
#        print "decrypt with: %s" % Hash('md5',key).hexdigest()

        xi = ciphers.xipher(key)

        return xi.decrypt(ciphertext)

    def public_encrypt(self,data,raw=True):
        keyindex = 1
        keyparts = {}
        tempkey = []
        
        for k in self.keys:
            pka = publickeyalgo.PublicKeyAlgorithm(k.get_publickey())

            # 加密部分密钥
            randomkey = ''
            for i in range(0,64):
                randomkey += chr(random.randint(0,255))
            randomkey = randomkey.encode('base64').replace('\n','')
            tempkey.append(randomkey)
            keyparts[keyindex] = serializer.loads(pka.encrypt(randomkey,self._encryptor))

            keyindex += 1

        tempkey.sort()
        #print "Before generation:"
        #print tempkey
        tempkey = "".join(tempkey)

        keydigest = Hash('md5',tempkey).digest()
        
        ciphertext = self._encryptor(tempkey,data)
        
        ret = {
            'Title':'Certificate_Encrypted_Text',
            'Certificate_ID':self.get_id(),
            'Key_Parts':keyparts,
            'Ciphertext':ciphertext,#.encode('base64'),
            'Key_Digest':keydigest,#.encode('base64'),
            }
        if not raw:
            ret = serializer.dumps(ret)
        return ret
    def private_decrypt(self,data):
        if not self.is_ours:

            log.exception('Unexcepted public certificate supplied for decrypting.')

            raise Exception("This is a public certificate and cannot be used for decrypting.")
        try:
            if type(data) == str:
                j = serializer.loads(data)
            else:
                j = data
            if j['Title'] != 'Certificate_Encrypted_Text':
                raise Exception("Not a encrypted text.")
            if j['Certificate_ID'] != self.get_id():
                raise Exception("Not for this certificate to decrypt.")
            ciphertext = j['Ciphertext']#.decode('base64')
            keyparts   = j['Key_Parts']
            keydigest  = j['Key_Digest']#.decode('base64')

            tempkey = []
            for sqid in keyparts:
                intsqid = int(str(sqid))
#                print intsqid
                pka = publickeyalgo.PublicKeyAlgorithm(self.keys[intsqid - 1].get_privatekey(False))
                randomkey = pka.decrypt(keyparts[sqid],self._decryptor)
#                print "   Temp Key Part(%s): %s" % (sqid,randomkey.encode('base64'))
                tempkey.append(randomkey)
            
            tempkey.sort()
#            print "After generation:"
#            print tempkey
            tempkey = "".join(tempkey)

            if Hash('md5',tempkey).digest() != keydigest:
                raise Exception("Failed to recover transfer key. Key exchanging failed.")
            #print tempkey.encode('hex')
            return self._decryptor(tempkey,ciphertext)
        except Exception,e:

            log.exception('Cannot decrypt using private certificate: %s',e)

            raise Exception("Decrypting Failure: %s" % e)
if __name__ == "__main__":
    failure = 0
    c = certificate()
    d = certificate()
    c.generate('NEO Example',level=50,bits=1024)
    d.generate('HMX Example',level=50,bits=1024)
    
    sig = c.sign_certificate(d,trustlevel=1)

#    d.load_signature(sig)

    print d.get_public_text()

    exit()

    c.save_private_text('neo.private')

    print c.get_public_text()

    exit()
    for i in range(0,100):
        print '##########################'
        try:

#    print c._decryptor('key',c._encryptor('key','hello,world!'))

#    exit()
#    print c.get_public_text()
#    d.load_private_text('alice.private')
            text = ''
            for j in range(0,128):
                text += chr(random.randint(0,255))
            ped = c.public_encrypt(text,True)
#    print ped
            print c.private_decrypt(ped)
        except:
            failure += 1
    print "Failed %d times." % failure
