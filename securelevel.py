# -*- coding: utf-8 -*-

# 提供一个咨询类，可以根据证书签名查明其可信程度

import os,sys
import certificate

BASEPATH = os.path.realpath(os.path.dirname(sys.argv[0]))

ROOTCERTPATH = os.path.join(BASEPATH,'user','rootcerts')
USERCERTPATH = os.path.join(BASEPATH,'user','usercerts')

class securelevel(object):
    indexes = {}
    foreigners = [] # 记录没见过的证书ID
    paths = []
    def __init__(self,rootpath=ROOTCERTPATH):
        # 缓存证书ID-文件关系
        # 根证书储存在   user/rootcerts 下面
        # 其他证书储存在 user/usercerts 下面
        if os.path.isdir(rootpath):
            self.paths.append((rootpath,True))
        else:
            raise Exception("No valid root cert. path specified:\n  %s" % rootpath)
    def trustlevel(self,consultresult,strict=False):
        # 根据 consult 的结果，计算 trustlevel
        # 如果 strict==False，则在同级签名中取信任等级最高的。
        levels = []
        
        for key in consultresult:
            plocation  = key.find('.')
            cert_id    = key[0:plocation]
            this_level = int(key[plocation+1:])

            # Get parents' trust level
            if type(consultresult[key]) == dict:
                parents_level = self.trustlevel(consultresult[key],strict)
            else:
                if consultresult[key] == True:
                    parents_level = this_level
                else:
                    parents_level = 0

#            if parents_level != True:
            this_level = min(parents_level,this_level)
            levels.append(this_level)
        if strict:
            return min(levels)
        else:
            return max(levels)
        
        
    def consult(self,pubcert):
        # 根据证书签名得知一个证书的一个或数个信任链
        # 一个信任链是一个 dict ，结构为：
        #  1) trust_level   最终计算出的建议信任等级，整型
        #  2) chain         list，依次记录从证书到根证书经过的各个证书的 (ID,Subject,TrustLevel)
        #  3) root          (ID,Subject)，信任链的根证书，如果是无效的（无根证书），则此项为空

        parents = self.walk(pubcert)
        if parents != []:
            ret = {}
            for i in range(0,len(parents)):
                item = parents[i]
                ret[item[0] + '.' + str(item[2])] = None
        else:
            pubcert_id = pubcert.get_id()
            pubcert_isroot = False
            if self.indexes.has_key(pubcert_id):
                pubcert_isroot = self.indexes[pubcert_id][1]
            ret = pubcert_isroot
        #print '<'
        #print ret
        if type(ret) == type({}):
            for key in ret:
                cr = self.consult(self.indexes[key[0:32]][0])
                ret[key] = cr
        #print ret
        #print '>'
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
                    print "Verified."
                    ret.append((issuer.get_id(),self.indexes[issuer_id][1],sig['Content']['Trust_Level']))
            else:
                self.foreigners.append(issuer_id)
        #print "Walk result of '%s':" % cert.subject
        #print ret
        return ret
    def initilize(self,paths):
        print "Caching all known certificates."
        for path in paths:
            self.paths.append((path,False))
        for pathtuple in self.paths:
            self._list_certs(pathtuple[0],pathtuple[1])
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
    a = securelevel(ROOTCERTPATH)
    a.initilize([USERCERTPATH,])
    
    c = certificate.certificate()

    c.load_public_text(open(USERCERTPATH + '/sl.pub').read())

    cr = a.consult(c)#,r)
    print cr
    
    print a.trustlevel(cr)
