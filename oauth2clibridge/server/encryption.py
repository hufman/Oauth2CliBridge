# From http://www.codekoala.com/posts/aes-encryption-python-using-pycrypto/
# From http://code.activestate.com/recipes/576980/

from Crypto.Cipher import AES
from Crypto.Util import randpool
from hashlib import sha1, sha256
import base64

BLOCK_SIZE = 16

def hash_sha1(data):
	hasher = sha1()
	hasher.update(data)
	return hasher.digest()

def hash_sha1_64(data):
	hasher = sha1()
	hasher.update(data)
	return hasher.hexdigest()

def hash_sha256(data):
	hasher = sha256()
	hasher.update(data)
	return hasher.digest()

def hash_sha256_64(data):
	hasher = sha256()
	hasher.update(data)
	return hasher.hexdigest()

def encrypt(key, decrypted):
	aes_key = hash_sha256(key)
	iv_bytes = randpool.RandomPool(512).get_bytes(BLOCK_SIZE)
	cipher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
	padding = BLOCK_SIZE - len(decrypted) % BLOCK_SIZE
	if padding == 0: padding = BLOCK_SIZE
	data = decrypted + padding * chr(padding)
	return base64.b64encode(iv_bytes + cipher.encrypt(data))

def decrypt(key, encrypted):
	aes_key = hash_sha256(key)
	encrypted_bytes = base64.b64decode(encrypted)
	iv_bytes = encrypted_bytes[0:BLOCK_SIZE]
	cipher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
	data = cipher.decrypt(encrypted_bytes[BLOCK_SIZE:])
	return data[:-ord(data[-1])]
