## EnMicroMsg.db password cracker

WARINING:  This tool should ONLY be used to crack your own db. DO NOT use it in ANY illegal circumstances.
## 微信安卓版数据库(EnMicroMsg.db)密码破解工具

(This tool may solve issues listed in [https://github.com/ppwwyyxx/wechat-dump/wiki](https://github.com/ppwwyyxx/wechat-dump/wiki), [pysqlcipher.dbapi2.DatabaseError: file is encrypted or is not a database](https://github.com/ppwwyyxx/wechat-dump/issues/21) )


With some devices, you may get the error message: "file is encrypted or is not a database", when trying to decrypt EnMicroMsg.db with "md5(imei + uin)[:7]". One possible reason is that WeChat uses other device IDs instead of IMEI to generate a password.

It is lucky for us that the 28-bit password (total 16^7 combinations) is not strong enough to resist brute-force attack. 

WeChat uses sqlcipher v2 to encrypt the database. Parts of the security features are listed as follows (from https://www.zetetic.net/sqlcipher/design/):

1. Each database page is encrypted and decrypted individually. This means we just need to handle the first 1024B, which is the default page size.
2. The default algorithm is 256-bit AES in CBC mode. 
3. Each page has it’s own initialization vector, which is stored at the last 16B.
4. Message authentication code (HMAC) is disabled in EnMicroMsg.db (see https://github.com/ppwwyyxx/wechat-dump/blob/master/decrypt-db.py, line 50). So we just ingore HMAC.
5. Then comes the time consuming part. The first 16 bytes of the file store the salt to derive the key (don't confuse this "key" and the 7 characters "passphrase"). In PBKDF2, 4000 iterations (sqlcipher v2, 64000 iterations for v3. Luckily WeChat uses the former version. 64000 iterations will cost much more time.) are used for key derivation.

So, the fellowing is our strategy:
get the first page; obtain IV from the last 16B and salt from the first 16B; iterate over all combinations of the possible passphrases; derivate the corresponding key. Decrypt the db. 

We know that the original header of sqlite db is a 16B string: "SQLite format 3\0", which is replaced by the salt in the encrypted case. Following are 2B to describe page size (0x04 0x00), 1B write version (~~0x01~~ 0x02) and 1B read version (~~0x01~~ 0x02). ~~We have 4 identical bytes to test whether we get the correct plain text.~~ (2019-04-12) From Wechat 7, Tencent user new write/read version (0x02), which will break our former detection. Now we will use the following three fixed bytes to test whether we get the correct plain text: 1. maximum embedded payload fraction (0x40) with offset 5; 2. minimum embedded payload fraction (0x20) with offset 6; 3. leaf payload fraction (0x20) with offset 7. (Here we can just ignore collision. If you successfully get the pass but still cannot open the db, just skip the "false alert" and start from the next pass.)

It takes about 5 ms to do a single PBKDF2 with 4000 iterations. So in the worst case, it will take 16^7 * 0.005 /3600/24 =  15.5 days to crack. On a 8-core PC, it reduces to 2 days (sounds reasonable now).


### How to use?:

Before cracking, please use [extract_key_from_cfg_files.py](#extract_key_from_cfg_files) to get the key if systemInfo.cfg and 
CompatibleInfo.cfg are available.

There are two versions to choose: a C version and a Python one. The former should be a bit faster (the core relies on openssl. No difference in calculating the 4000 iterations).

#### C version:
1. install openssl dev package (tested with openssl 1.0.2g and openssl 1.1.0.g [(issue #4)](https://github.com/chg-hou/EnMicroMsg.db-Password-Cracker/issues/4)  ):
```
    $ sudo apt-get install libssl-dev
```
2. compile password_cracker.c :
```
    $ gcc password_cracker.c  -l crypto -o password_cracker.o
```
3. modify parameters in "crack_enmicromsg_db_(C_version)".
    process_no:  total cores used.
    Note: If you successful get the pass but still cannot open the db, start from the next pass by change "pass_start".
    
4. start:
```
    $ python2 crack_enmicromsg_db_\(C_version\).py
```
#### Python version:
##### Dependencies:
+ [pysqlcipher](https://pypi.python.org/pypi/pysqlcipher)

Demo purpose. Not well written.

### Got the pass, and then?
Use the wonderful [wechat-dump](https://github.com/ppwwyyxx/wechat-dump) written by Yuxin Wu  to dump the whole db. You need to tweak a few lines in "decrypt-db.py" to use the key. Have fun!

### Scripts in tools folder

+ [decrypt_db_with_password.py](https://github.com/chg-hou/EnMicroMsg.db-Password-Cracker/blob/master/tools/decrypt_db_with_password.py): when you have already known the password, use this script to get an decrypted database which can be viewed/edited by [DB Browser for SQLite](http://sqlitebrowser.org/).

+ [encrypt_db_again.py](https://github.com/chg-hou/EnMicroMsg.db-Password-Cracker/blob/master/tools/encrypt_db_again.py): encrypting the db again. Note: (2018 Feb 04) not tested whether WeChat can open it correctly. 

+ [extract_key_from_cfg_files.py](https://github.com/chg-hou/EnMicroMsg.db-Password-Cracker/blob/master/tools/extract_key_from_cfg_files.py) <a name="extract_key_from_cfg_files"></a>: this script can extract key from **CompatibleInfo.cfg** and **systemInfo.cfg**. Please note that it is written in **Python 3**. Change the search_path first and then run the script with 
```
    $ python3 extract_key_from_cfg_files.py
```

+ [GetDBKey.class](https://github.com/chg-hou/EnMicroMsg.db-Password-Cracker/blob/master/tools/GetDBKey.class): a java code can do the same work as extract_key_from_cfg_files.py. Copy from [https://bbs.pediy.com/thread-250714.htm](https://bbs.pediy.com/thread-250714.htm).


### Acknowledge
[sqlcipher-tools/decrypt.c](https://github.com/sqlcipher/sqlcipher-tools/blob/master/decrypt.c) helps me a lot to understand how sqlcipher works.

[wechat-dump/decrypt-db.py](https://github.com/ppwwyyxx/wechat-dump/blob/master/decrypt-db.py) provides key parameters of WeChat db.

[sqlcipher documentation](https://www.zetetic.net/sqlcipher/design/) : its detailed security features.

[Fix issue #4: Will not compile against openssl 1.1](https://github.com/chg-hou/EnMicroMsg.db-Password-Cracker/issues/4) : thanks [@couling](https://github.com/couling) for the openssl 1.1 patch.
