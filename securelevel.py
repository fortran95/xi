# -*- coding: utf-8 -*-

# 提供一个咨询类，可以根据证书签名查明其可信程度

import os,sys
import certificate

BASEPATH = os.path.dirname(sys.argv[0])
if BASEPATH != '':
    BASEPATH += '/'
ROOTCERTPATH = BASEPATH + 'user/rootcerts'
USERCERTPATH = BASEPATH + 'user/usercerts'

class securelevel(object):
    indexes = {}
    def __init__(self):
        # 缓存证书ID-文件关系
        # 根证书储存在   user/rootcerts 下面
        # 其他证书储存在 user/usercerts 下面
        print "Initializing Secure Consultant."
        self.initilize()
    def consult(self,pubcert):
        # 根据证书签名得知一个证书的一个或数个信任链
        # 一个信任链是一个 dict ，结构为：
        #  1) trust_level   最终计算出的建议信任等级，整型
        #  2) chain         list，依次记录从证书到根证书经过的各个证书的 (ID,Subject,TrustLevel)
        #  3) root          (ID,Subject)，信任链的根证书，如果是无效的（无根证书），则此项为空
        ret = self.walk(pubcert)
        if ret != []:
            for i in range(0,len(ret)):
                item = ret[i]
                consult_result = self.consult(self.indexes[item[0]][0])
                if consult_result != []:
                    ret[i] = consult_result
        return ret
    def walk(self,cert):
        cert_level = cert.level
        ret = []
        for sig in cert.signatures:
            issuer_id = sig['Content']['Issuer_ID']
            if self.indexes.has_key(issuer_id):
                issuer = self.indexes[issuer_id][0]
                if issuer.level <= cert_level:
                    continue
                if issuer.verify_signature(sig):
                    # 得到了本证书的一个上级证书，并且通过了验证
                    ret.append((issuer.get_id(),self.indexes[issuer_id][1]))
        return ret
    def initilize(self):
        print "Caching all known certificates."
        self._list_certs(ROOTCERTPATH,True)
        self._list_certs(USERCERTPATH)
    def _list_certs(self,path,isroot=False):
        listresult = os.listdir(path)
        for filename in listresult:
            pathname = os.path.join(path,filename)
            if not os.path.isfile(pathname):
                continue
            try:
                c       = certificate.certificate()
                c_cont  = open(pathname,'r').read()

                c.load_public_text(c_cont)

                c_id    = c.get_id()
            except:
                continue
            self.indexes[c_id] = (c,isroot)

if __name__ == '__main__':
    a = securelevel()
    c = certificate.certificate()

    c.load_public_text(open(USERCERTPATH + '/1').read())

    print a.consult(c)
