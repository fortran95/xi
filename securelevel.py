# -*- coding: utf-8 -*-

# 提供一个咨询类，可以根据证书签名查明其可信程度

BASEPATH = os.path.dirname(sys.argv[0])
if BASEPATH != '':
    BASEPATH += '/'
ROOTCERTPATH = BASEPATH + 'userconf/rootcerts'

class securelevel(object):
    def __init__(self):
        # 缓存证书ID-文件关系
        # 根证书储存在   user/rootcerts 下面
        # 其他证书储存在 user/usercerts 下面
        pass
    def consult(self,pubcert):
        # 根据证书签名得知一个证书的一个或数个信任链
        # 一个信任链是一个 dict ，结构为：
        #  1) trust_level   最终计算出的建议信任等级，整型
        #  2) chain         list，依次记录从证书到根证书经过的各个证书的 (ID,Subject,TrustLevel)
        #  3) root          (ID,Subject)，信任链的根证书，如果是无效的（无根证书），则此项为空
        pass

class trustchain(object):
    chain = []
    def __init__(self):
        pass
    def append(self,pubcert):
        # 在信任链中添加一环，返回本环的前一级
