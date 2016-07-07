from argparse import ArgumentParser
from pysqlcipher import dbapi2 as sqlite

from hashlib import md5

db = 'EnMicroMsg.db'

key = '00001ef'

conn = sqlite.connect(db)
c = conn.cursor()
c.execute("PRAGMA key = '" + key + "';")
c.execute("PRAGMA cipher_use_hmac = OFF;")
c.execute("PRAGMA cipher_page_size = 1024;")
c.execute("PRAGMA kdf_iter = 4000;")

c.execute("create table test_table (test_col text primary key)")

c.close()
