#-*- coding: utf-8 -*-

# ����һЩ��ȫ����

import os,sys

def check():
    pass

def is_on_ramfs():
    # ����Ƿ��Ѿ�������Ž� RAMFS ��������
    status = os.popen('mount | grep ramfs').readlines()
    mypath = os.path.realpath('')
    
    for ramdiskline in status:
        if ramdiskline.find('%s type ramfs (rw' % mypath) >= 0:
            return True
    return False

if __name__ == "__main__":
    if not is_on_ramfs():
        print "Warning: Xi Program is NOT working on RAMDISK!"
