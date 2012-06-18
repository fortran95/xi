#-*- coding: utf-8 -*-

# 监视一些安全参数

import os,sys

def check():
    pass

def is_on_ramfs():
    # 检查是否已经将程序放进 RAMFS 进行运行
    status = os.popen('mount | grep ramfs').readlines()
    mypath = os.path.realpath('')
    
    for ramdiskline in status:
        if ramdiskline.find('%s type ramfs (rw' % mypath) >= 0:
            return True
    return False

if __name__ == "__main__":
    if not is_on_ramfs():
        print "Warning: Xi Program is NOT working on RAMDISK!"
