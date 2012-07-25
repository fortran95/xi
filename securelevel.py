# -*- coding: utf-8 -*-

# �ṩһ����ѯ�࣬���Ը���֤��ǩ����������ų̶�

import os,sys
import certificate

BASEPATH = os.path.realpath(os.path.dirname(sys.argv[0]))

ROOTCERTPATH = os.path.join(BASEPATH,'user','rootcerts')
USERCERTPATH = os.path.join(BASEPATH,'user','usercerts')

class securelevel(object):
    indexes = {}
    foreigners = [] # ��¼û������֤��ID
    paths = []
    def __init__(self,rootpath=ROOTCERTPATH):
        # ����֤��ID-�ļ���ϵ
        # ��֤�鴢����   user/rootcerts ����
        # ����֤�鴢���� user/usercerts ����
        if os.path.isdir(rootpath):
            self.paths.append((rootpath,True))
        else:
            raise Exception("No valid root cert. path specified:\n  %s" % rootpath)
    def trustlevel(self,consultresult,strict=False):
        # ���� consult �Ľ�������� trustlevel
        # ��� strict==False������ͬ��ǩ����ȡ���εȼ���ߵġ�
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
        # ����֤��ǩ����֪һ��֤���һ��������������
        # һ����������һ�� dict ���ṹΪ��
        #  1) trust_level   ���ռ�����Ľ������εȼ�������
        #  2) chain         list�����μ�¼��֤�鵽��֤�龭���ĸ���֤��� (ID,Subject,TrustLevel)
        #  3) root          (ID,Subject)���������ĸ�֤�飬�������Ч�ģ��޸�֤�飩�������Ϊ��

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
                    # �õ��˱�֤���һ���ϼ�֤�飬����ͨ������֤
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
