import json, os, time
from cryptography.fernet import Fernet
from _md5 import md5
from pathlib import Path

__doc__ = """OpenBLC is a simple python blockchain constructor.
In order to create an instance of the blockchain, it is enough to call Blockchain() and pass several attributes to it.
blc = Blockchain("my_blc") in the first attribute, you need to specify the path to the folder with the blockchain, 
the last segment of which should be a folder with the same name as the blockchain. You can pass the doenc parameter 
with a boolean value. He is responsible for blockchain encryption. If you want to use encryption, you also need to 
pass the secret parameter, which accepts the Fernet key. Fernet key must be 32 url-safe base64-encoded bytes. 
The encryption parameter takes a reference to the hash function and the posten parameter indicates the attribute 
that should be called from the hash function. If calling an additional attribute is not required, specify None. 
The md5 hash function is used by default.
get() returns data from the block.
Accepts the block id as input and optionally the cleared flag, which removes system information from the response.

Example:

from _sha512 import sha512
from OpenBLC import Blockchain

def my_encryptor(data):
	return sha512(data).hexdigest()

data = {
	'text': 'Test Data'
}

blc = Blockchain("my_blc", encryption = my_encryptor, doenc = True, postenc = None, secret = b'Fy24XsoZgW29VxpSIkAuXD-655SRVwaIrAFFA97KDfg=')

print(f'Index block: {blc.calculate_index()}')
print(f'Corruption state: {blc.chain_check()}')
print(f'Manifest state: {blc.check_manifest()}')

blc.add(data)

for i in range(blc.calculate_index()):
	print(blc.get(i, True))


calculate_index() returns the number of the last block. 
chain_check() checks the integrity of the chain. If everything is in order, it returns True, otherwise it returns the numbers of damaged blocks. 
check_manifest() checks the integrity of the blockchain manifest.

feedback: btomaev34@gmail.com
"""

def sint(a):
	a = str(a)
	b = ""
	for i in range(len(a)):
		if(a[i].isdigit()):
			b+=a[i]
	return int(b)

class Blockchain():
	def __init__(self, path, encryption = md5, postenc = "hexdigest", doenc = True, secret = b'CsfXxv9BNAn50WY4Af2S-bQinXdypdYVALHIh-DSaKI='):
		self.path = Path(path)
		self.encryption = encryption
		self.postenc = postenc
		self.name = self.path.name
		self.__secret = secret
		self.doenc = doenc
		self.__sail = str(self.__secret)+self.name
		self.blc_path = Path(self.path, "blockchain")
		self.manifest_path = Path(self.path, f'{self.name}.blc')
		if(self.manifest_path.exists() and self.manifest_path.is_file()):
			if(not self.check_manifest() == True):
				raise Exception(f"The blockchain manifest error: {self.check_manifest()}. Access denied!")
		else:
			self.__init_blockchain()

	def add(self, data):
		index = self.calculate_index()
		if(index == 0):
			hash_field = ''
		else:
			hash_field = self.__get_hash(str(self.__read(Path(self.blc_path, f'{index-1}.blcitem'))).encode())
		base = {
		'hash_field': hash_field,
		'time': time.time(),
		}
		base.update(data)
		self.__write(base, Path(self.blc_path, f'{index}.blcitem'), "x")
		manifest_data = self.__read(self.manifest_path)
		manifest_data['current_index'] = index+1
		self.__write(manifest_data, self.manifest_path)

	def get(self, id, cleared = False):
		try:
			manifest_data = self.__read(Path(self.blc_path, f'{id}.blcitem'))
			if(cleared):
				manifest_data.pop("hash_field")
				manifest_data.pop("time")
			return manifest_data
		except FileNotFoundError:
			raise Exception(f'Block {id} not found')

	def __encrypt(self, data, key):
		data = str(data).encode()
		return Fernet(key).encrypt(data)

	def __decrypt(self, data, key):
		return Fernet(key).decrypt(data)

	def __read(self, path):
		with open(path, 'r') as file:
			data = file.read()
			if(self.doenc):
				data = self.__decrypt(data[3:-2].encode(), self.__secret).decode().replace("'",'"')
			return json.loads(data)

	def __write(self, data, path, mode = "w"):
		with open(path, mode) as file:
			if(self.doenc):
				data = str(self.__encrypt(data, self.__secret))
			return json.dump(data, file)

	def __get_hash(self, data):
		enc = self.encryption(data)
		if(not self.postenc==None):
			enc = getattr(enc, self.postenc)()
		return enc

	def __init_blockchain(self):
		if((not self.path.exists()) or (not self.path.is_dir())):
			os.mkdir(self.path)
		if((not self.blc_path.exists()) or (not self.blc_path.is_dir())):
			os.mkdir(self.blc_path)
		data = {
			"current_index": 0,
			"name": self.name,
			"encryption": self.encryption.__name__,
			"check": self.__get_hash(self.__sail.encode()),
		}
		self.__write(data, self.manifest_path, "x")

	def check_manifest(self):
		data = self.__read(self.manifest_path)
		if(not data['name'] == self.name):
			return "NAME_IS_OUT"
		elif(not data['encryption'] == self.encryption.__name__):
			return "ENCRYPTION_IS_OUT"
		elif(not data['current_index'] == self.calculate_index()):
			return "INDEX_IS_OUT"
		elif(not data['check'] == self.__get_hash(self.__sail.encode())):
			return "CHECK_IS_OUT"
		else:
			return True

	def calculate_index(self):
		items = list(self.blc_path.glob("*.blcitem"))
		if(len(items)==0):
			return 0
		check = self.chain_check()
		if(check==True):
			return len(items)
		elif(check==False):
			raise Exception(f"The blockchain is empty. Access denied!")
		else:
			corrupted = ''
			for i in check:
				corrupted+=i+" "
			raise Exception(f"The block number's {corrupted}is corrupted. Access denied!")

	def chain_check(self):
		items = sorted(list(self.blc_path.glob("*.blcitem")), key=sint)
		corrupted = []
		if(len(items)==0):
			return False
		i = 0
		for item in items:
			if(not i == int(item.stem)):
				for n in range(int(item.stem)-i):
					corrupted.append(str(i)) 
					i+=1
				i+=1
				continue
			last = Path(self.blc_path, f'{i-1}.blcitem')
			if(last.exists()):
				hash_field = self.__get_hash(str(self.__read(last)).encode())
				manifest_data = self.__read(item)
				if(not manifest_data['hash_field'] == hash_field):
					corrupted.append(str(i-1))
			i+=1
		if(len(corrupted)>0):
			return corrupted
		else:
			return True