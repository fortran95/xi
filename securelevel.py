# -*- coding: utf-8 -*-

# �ṩһ����ѯ�࣬���Ը���֤��ǩ����������ų̶�

BASEPATH = os.path.dirname(sys.argv[0])
if BASEPATH != '':
    BASEPATH += '/'
ROOTCERTPATH = BASEPATH + 'userconf/rootcerts'

class securelevel(object):
    def __init__(self):
        # ����֤��ID-�ļ���ϵ
        # ��֤�鴢����   user/rootcerts ����
        # ����֤�鴢���� user/usercerts ����
        pass
    def consult(self,pubcert):
        # ����֤��ǩ����֪һ��֤���һ��������������
        # һ����������һ�� dict ���ṹΪ��
        #  1) trust_level   ���ռ�����Ľ������εȼ�������
        #  2) chain         list�����μ�¼��֤�鵽��֤�龭���ĸ���֤��� (ID,Subject,TrustLevel)
        #  3) root          (ID,Subject)���������ĸ�֤�飬�������Ч�ģ��޸�֤�飩�������Ϊ��
        pass

class trustchain(object):
    chain = []
    def __init__(self):
        pass
    def append(self,pubcert):
        # �������������һ�������ر�����ǰһ��
