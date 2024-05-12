#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from unicrypto import hashlib
from unicrypto.symmetric import RC4, AES, MODE_CBC, expand_DES_key, DES

from pypykatz.registry import logger
from pypykatz.registry.sam.common import SAMSecret
from pypykatz.registry.sam.structures import SAM_HASH, DOMAIN_ACCOUNT_F,\
	SAM_KEY_DATA, SAM_KEY_DATA_AES, USER_ACCOUNT_V, SAM_HASH_AES


#
# The SAM hive holds the hashed passwords of the LOCAL machine users
# There are alwas some local users present on your machine, regardless if it's domain-enrolled
# 
# Depending on the Windows version, the strucutres and the way to decrypt the hashes differs.
# The class needs to have the bootkey (see SYSTEM hive) to be able to decrypt the hashes
#

class SAM:
	def __init__(self, sam_hive, bootkey):
		self.hive = sam_hive
		self.bootkey = bootkey
		self.hashed_bootkey = None
		self.machine_sid = None
		self.secrets = []
		
	@staticmethod
	def rid_to_key(rid):
		key = int(rid, 16).to_bytes(4, 'little', signed = False)
		key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
		key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
		return expand_DES_key(bytes(key1)),expand_DES_key(bytes(key2))
		
	def decrypt_hash(self, rid, hashobj, constant):
		key1, key2 = SAM.rid_to_key(rid)
		des1 = DES(key1)
		des2 = DES(key2)
		
		if isinstance(hashobj, SAM_HASH):
			rc4key = hashlib.md5( self.hashed_bootkey[:0x10] + int(rid, 16).to_bytes(4, 'little', signed = False) + constant ).digest()
			key = RC4(rc4key).encrypt(hashobj.hash)
			
		else:
			key = b''
			cipher = AES(self.hashed_bootkey[:0x10], MODE_CBC, IV = hashobj.salt)
			n = 16
			for block in [hashobj.data[i:i+n] for i in range(0, len(hashobj.data), n)]:  #terrible, terrible workaround
				key += cipher.decrypt(block)
					
			key = key[:16]
			
		dec_hash = des1.decrypt(key[:8]) + des2.decrypt(key[8:])
		return dec_hash
		
	async def get_HBoot_key(self):
		logger.debug('SAM parsing hashed bootkey')
		QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
		DIGITS = b"0123456789012345678901234567890123456789\0"
		
		F = await self.hive.get_value(r'SAM\Domains\Account\F')
		F = F[1]
		logger.log(1,'[SAM] F key value: %s' % F)
		
		domain_properties = DOMAIN_ACCOUNT_F.from_bytes(F)
		
		if isinstance(domain_properties.key_0, SAM_KEY_DATA):
			rc4_key = hashlib.md5(domain_properties.key_0.salt + QWERTY + self.bootkey +DIGITS).digest()
			self.hashed_bootkey = RC4(rc4_key).encrypt(domain_properties.key_0.key + domain_properties.key_0.checksum)
			
			checksum = hashlib.md5(self.hashed_bootkey[:16] + DIGITS + self.hashed_bootkey[:16] + QWERTY).digest()
			
			if checksum != self.hashed_bootkey[16:]:
				logger.error('[SAM] HBootkey checksum verification failed!')
				raise Exception('[SAM] HBootkey checksum verification failed!')
				
		elif isinstance(domain_properties.key_0, SAM_KEY_DATA_AES):
			self.hashed_bootkey = b''
			cipher = AES(self.bootkey, MODE_CBC, IV = domain_properties.key_0.salt)
			n = 16
			for block in [domain_properties.key_0.data[i:i+n] for i in range(0, len(domain_properties.key_0.data), n)]:  #terrible, terrible workaround
				self.hashed_bootkey += cipher.decrypt(block)
			
		logger.debug('[SAM] HBootkey: %s' % self.hashed_bootkey.hex())
		return self.hashed_bootkey
		
	async def get_machine_sid(self):
		# https://social.technet.microsoft.com/Forums/en-US/de8ff30b-6986-4aad-bcde-12bb5e66fe86/the-computer-sid-with-windows-7?forum=winserverDS
		# TODO: implement this
		try:
			uac_data = await self.hive.get_value('SAM\\Domains\\Account\\V')
			uac_data = uac_data[1]
			uac_data = uac_data[-12:]
			p1 = int.from_bytes(  uac_data[:4], 'little', signed = False)
			p2 = int.from_bytes( uac_data[4:8], 'little', signed = False)
			p3 = int.from_bytes(uac_data[8:12], 'little', signed = False)
			self.machine_sid = '%s-%s-%s-%s' % ('S-1-5-21', p1, p2, p3)
		except Exception as e:
			import traceback
			traceback.print_exc()
		return self.machine_sid
		
	async def get_secrets(self):
		logger.debug('SAM get_secrets invoked')
		NTPASSWORD = b"NTPASSWORD\0"
		LMPASSWORD = b"LMPASSWORD\0"
		
		NTDEFAULT = '31d6cfe0d16ae931b73c59d7e0c089c0'
		LMDEFAULT = 'aad3b435b51404eeaad3b435b51404ee'
		
		await self.get_HBoot_key()
		await self.get_machine_sid()
		
		names = await self.hive.enum_key('SAM\\Domains\\Account\\Users')
		for rid in names:
			uac = None
			if rid == 'Names':
				continue
			
			key_path = 'SAM\\Domains\\Account\\Users\\%s\\V' % rid
			logger.debug('[SAM] Parsing secrets for RID: %s' % rid)
			uac_data = await self.hive.get_value(key_path)
			uac_data = uac_data[1]
			uac = USER_ACCOUNT_V.from_bytes(uac_data)
			
			nthash = bytes.fromhex(NTDEFAULT)
			lmhash = bytes.fromhex(LMDEFAULT)
			if uac.NT_hash and isinstance(uac.NT_hash, SAM_HASH_AES):
				if uac.NT_hash.data != b'':
					nthash = self.decrypt_hash(rid, uac.NT_hash, NTPASSWORD)
			elif uac.NT_hash and isinstance(uac.NT_hash, SAM_HASH):
				if uac.NT_hash.hash != b'':
					nthash = self.decrypt_hash(rid, uac.NT_hash, NTPASSWORD)
			
			if uac.LM_hash and isinstance(uac.LM_hash, SAM_HASH_AES):
				if uac.LM_hash.data != b'':
					lmhash = self.decrypt_hash(rid, uac.LM_hash, LMPASSWORD)
			
			elif uac.LM_hash and isinstance(uac.LM_hash, SAM_HASH):
				if uac.LM_hash.hash != b'':
					lmhash = self.decrypt_hash(rid, uac.LM_hash, LMPASSWORD)
			
			secret = SAMSecret(uac.name, int(rid,16), nthash, lmhash)
			self.secrets.append(secret)
			
		return self.secrets
		
	def to_dict(self):
		t = {}
		t['HBoot_key'] = self.hashed_bootkey
		t['local_users'] = []
		for secret in self.secrets:
			t['local_users'].append( secret.to_dict())
		return t
		
	def __str__(self):
		t  = '============== SAM hive secrets ==============\r\n'
		t += 'HBoot Key: %s\r\n' % self.hashed_bootkey.hex()
		for secret in self.secrets:
			t += '%s\r\n' % secret.to_lopth()
		return t

		
