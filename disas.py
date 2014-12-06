import pefile
import redis
from capstone import *
import os
import threading
import Queue
import sys
from zipfile import ZipFile

def disas_file(path,db):
	pipe = db.pipeline()
	total = 0
	try:
		pe = pefile.PE(data=path, fast_load=True)
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
		data=pe.get_memory_mapped_image()[ep:]
		count = {}
		md = Cs(CS_ARCH_X86, CS_MODE_64)
		for i in md.disasm(data, ep_ava):
			mnemonic = i.mnemonic
			if mnemonic not in count:
				count[mnemonic] = 1
			else:
				count[mnemonic] += 1
			total+=1
		for key in count:
			pipe.incr(key,amount=count[key])
	except:
		pass
	pipe.incr('total',amount=total)
	pipe.execute()

def disas_files(redis_db,queue):
	r_server = redis.Redis('localhost',db=redis_db)
	while True:
		item = queue.get()
		disas_file(item,r_server)
		queue.task_done()


def disas_zip_files(redis_db,queue):
	r_server = redis.Redis('localhost',db=redis_db)
	while True:
		item = queue.get()
		disas_file(item.read(),r_server)
		queue.task_done()

work = Queue.Queue()
t = threading.Thread(target=disas_files,args=(0,work))
t.daemon = True
t.start()
files = os.listdir('clean')
for i in files:
	work.put(open(os.path.join('clean',i)).read())

work.join()

malware_queue = Queue.Queue()
r_server = redis.Redis('localhost',db=1)
t = threading.Thread(target=disas_zip_files,args=(1,malware_queue))
t.daemon = True
t.start()

with ZipFile('malware.zip', 'r') as f:
	f.setpassword('infected')
	for name in f.namelist():
		malware_queue.put(f.open(name))

malware_queue.join()

sys.exit()