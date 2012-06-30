# -*- coding: utf-8 -*-

# �ṩһ����ѯ�࣬���Ը���֤��ǩ����������ų̶�

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
        # ����֤��ID-�ļ���ϵ
        # ��֤�鴢����   user/rootcerts ����
        # ����֤�鴢���� user/usercerts ����
        print "Initializing Secure Consultant."
        self.initilize()
    def consult(self,pubcert):
        # ����֤��ǩ����֪һ��֤���һ��������������
        # һ����������һ�� dict ���ṹΪ��
        #  1) trust_level   ���ռ�����Ľ������εȼ�������
        #  2) chain         list�����μ�¼��֤�鵽��֤�龭���ĸ���֤��� (ID,Subject,TrustLevel)
        #  3) root          (ID,Subject)���������ĸ�֤�飬�������Ч�ģ��޸�֤�飩�������Ϊ��

        pass
    def walk(self,cert):
        cert_level = cert.level
        for sig in cert.signatures:
            issuer_id = sig['Content']['Issuer_ID']
            if self.indexes.has_key(issuer_id):
                issuer = self.indexes[issuer_id][0]
                if issuer.level <= cert_level:
                    continue
                if issuer.verify_signature(sig):
                    # �õ��˱�֤���һ���ϼ�֤�飬����ͨ������֤
                    pass
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

    a.walk(c)
