# -*- coding: utf-8 -*-

# �ṩһ����ѯ�࣬���Ը���֤��ǩ����������ų̶�
# �����userconf/rootcerts�д���ĸ�֤�齻����

BASEPATH = os.path.dirname(sys.argv[0])
if BASEPATH != '':
    BASEPATH += '/'
ROOTCERTPATH = BASEPATH + 'userconf/rootcerts'

class securelevel(object):
    def __init__(self):
        # �����֤��
        # ��֤������ǩ���ģ��Ա���������ȷ�ϣ�
        
