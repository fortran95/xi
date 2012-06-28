# -*- coding: utf-8 -*-

# 提供一个咨询类，可以根据证书签名查明其可信程度
# 本类和userconf/rootcerts中储存的根证书交互。

BASEPATH = os.path.dirname(sys.argv[0])
if BASEPATH != '':
    BASEPATH += '/'
ROOTCERTPATH = BASEPATH + 'userconf/rootcerts'

class securelevel(object):
    def __init__(self):
        # 缓存根证书
        # 根证书是自签名的（以便有完整性确认）
        
