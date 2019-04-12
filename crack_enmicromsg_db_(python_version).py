#!/usr/bin/env python2


'''15fbee0 '''
# ======================== Edit checkpoint and process_no==================
checkpoint = '995'  # first three chars to start from
process_no = 16
# ========================================================================


import os, sys
import threading
import multiprocessing
import itertools
from argparse import ArgumentParser
from pysqlcipher import dbapi2 as sqlite

from hashlib import md5



TOTAL_KEY_LENGTH = 7
PROCESS_KEY_LENGTH = 3

db = 'EnMicroMsg.db'
output = 'output_db.db'

def worker(id, prefix):
    import itertools, time
    print ('-------------id: %d  ===== prefix: %s' % (id, prefix))
    if os.path.exists(output):
        return  'Alread Done.'

    a = time.time()
    str_list = '0123456789abcdef'
    key_length = TOTAL_KEY_LENGTH - PROCESS_KEY_LENGTH
    count = 0
    for i in itertools.product(str_list, repeat=key_length):
        count += 1
        key = prefix + ''.join(i)
        try:
            conn = sqlite.connect(db)
            c = conn.cursor()

            c.execute("PRAGMA key = '" + key + "';")
            c.execute("PRAGMA cipher_use_hmac = OFF;")
            c.execute("PRAGMA cipher_page_size = 1024;")
            c.execute("PRAGMA kdf_iter = 4000;")
            c.execute("SELECT name FROM sqlite_master WHERE type='table'")

            c.execute("ATTACH DATABASE '" + output + "' AS db KEY '';")
            c.execute("SELECT sqlcipher_export('db');")
            c.execute("DETACH DATABASE db;")
            print "Decrypt and dump database to {} ... ".format(output)
            print key
            print('OK!!!!!!!!!')
            with open('CRACKED_PASS.txt', 'a') as f:
                f.write(key)
                f.write('\n')
            break
        except Exception as e:
            # print(str(e))
            pass
        finally:
            conn.close()

        # if count > count_limit:
        #     break
        if count % 100000 == 0:
            p = 1.0 * count / 16 ** key_length
            b = time.time() - a
            rt = b / (p + 0.0000001) * (1 - p)
            print('%d: %f %%, time: %f s, end time: %f s' % (id, p * 100,
                                                             b,
                                                             rt)
                  )
            print(key)

    b = time.time() - a
    print('%d: Total time: %f s, per loop: %f s, speed: %f 1/s' % (id, b, b / count, count / b))
    return '%d Done' % (id)

DEFAULT_OUTPUT_DB_NAME = 'decrypted.db'

if __name__ == '__main__':

    str_list = '0123456789abcdef'
    key_length1 = PROCESS_KEY_LENGTH

    # Multi-process
    record = []
    result = []
    pool = multiprocessing.Pool(processes=process_no)
    id_a = 0
    
    RECOVERED_FLAG = True if checkpoint=='' else False
    
    for i in itertools.product(str_list, repeat=key_length1):
        prefix = ''.join(i)
        
        if not RECOVERED_FLAG:
            if prefix != checkpoint:
                continue
            else:
                print("Continue from "+checkpoint)
                RECOVERED_FLAG = True
        
        result.append(pool.apply_async(worker, (id_a, prefix)))
        id_a += 1
        if os.path.exists(output):
            print  'Alread Done.'
            break

    pool.close()
    pool.join()
    for res in result:
        print res.get()
    print "Sub-process(es) done."
