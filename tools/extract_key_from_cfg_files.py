#!/usr/bin/env python3


# ======================= Edit search_path==========
search_path = './'
# ==================================================


import glob,struct,os,hashlib
for filename in glob.iglob(os.path.join(search_path,'./**/systemInfo.cfg'),
                           recursive=True):
    print(filename)
    int_object_header = b'\x73\x71\x00\x7e\x00\x02'
    with open(filename, 'rb') as f:
        s = f.read()
    idx = s.find(int_object_header) + len(int_object_header)
    uin = struct.unpack('>i',s[idx :idx + 4])[0]
    uin = str(uin)
    print('\t'+'uin:  ',uin)
    
    for filename in glob.iglob(os.path.join(search_path,'./**/CompatibleInfo.cfg'),
                               recursive=True):
        print('\t'+filename)   
        str_object_header = b'\x74\x00\x10'
        with open(filename, 'rb') as f:
            s = f.read()
        idx = 0
        for _ in range(2):
            # get the second string
            idx = s.find(str_object_header,idx) + len(str_object_header)
        idx_end = s.find(int_object_header,idx)
        IMEI = s[idx:idx_end].decode('ascii')
        print('\t\t'+'IMEI: ',IMEI)
        
        password = hashlib.md5((IMEI+uin).encode()).hexdigest()[:7]
        print('\t\t'+'pass: ',password)
