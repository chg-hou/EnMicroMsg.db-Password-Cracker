# 1. install openssl dev package:
#    $ sudo apt-get install libssl-dev

# 2. compile password_cracker.c:
#    $ gcc password_cracker.c  -l crypto -o password_cracker.o

# 3. modify following parameters in this file and then run.

db_file_name = 'EnMicroMsg.db'
pass_file_name = 'pass.txt'
process_no = 4

pass_start = 0x0000000
pass_end =   0xfffffff
pass_truck_size = 4000


# ====================================


import threading
import time, os
import Queue, subprocess

pass_seg = Queue.Queue()
bin_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),'password_cracker.o')

class workerThread(threading.Thread):
    def __init__(self, threadID, name, pass_seg_):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.pass_seg = pass_seg_

    def run(self):
        print('Thread %d started...' % (self.threadID))
        while not pass_seg.empty():
            sn_start, sn_end = self.pass_seg.get()
            if sn_start is None:
                break
            if os.path.exists(pass_file_name):
                break
            print(subprocess.check_output([bin_path, db_file_name,
                                           pass_file_name,
                                          hex(sn_start), hex(sn_end)]))


if os.path.exists(pass_file_name):
    print('Pls delete %s and then try again.' % (pass_file_name))
    exit(0)

if not os.path.exists(bin_path):
    print('Code has NOT been complied. Pls complie it first.')
    exit(0)

while pass_start<= pass_end:
    pass_seg.put((pass_start,min(pass_start+pass_truck_size-1, pass_end)))
    pass_start += pass_truck_size

thread_pool =[]
for i in range(process_no):
    thread_pool.append( workerThread(i, 'Worker %d' % i, pass_seg))

[x.start() for x  in thread_pool]

[x.join() for x in thread_pool]

print("Exiting Main Thread")