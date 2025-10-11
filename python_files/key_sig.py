import math
from .nds_rom_header_wii_data import *
from .utils import *

# This file contains the basic data regarding the various key types,
# as well as classes to obtain such information.

sig2048_type = [0x00, 0x01, 0x00, 0x01]
sig4096_type = [0x00, 0x01, 0x00, 0x00]
sigecdh_type = [0x00, 0x01, 0x00, 0x02]
rsa_2048_size = 0x100
rsa_4096_size = 0x200
ecdh_size = 0x3C
sig_type_size = len(sig2048_type)
signature_pos = sig_type_size

pubkey_pos = 0x88

rsa2048_type = [0x00, 0x00, 0x00, 0x01]
rsa4096_type = [0x00, 0x00, 0x00, 0x00]
ecdh_type = [0x00, 0x00, 0x00, 0x02]
key_type_size = len(rsa2048_type)
rsa_2048_pub_exp_dsi_size = 4
rsa_4096_pub_exp_dsi_size = 4
ecdh_pub_exp_dsi_size = 0

# Information related to the key which will be signed or has been signed.
class KeyForSigningKind:
	def __init__(self, kind, type_bytes, modulus_size, pub_exp_size):
		self.kind = kind
		self.type_bytes = type_bytes
		self.modulus_size = modulus_size
		self.pub_exp_size = pub_exp_size
		self.key_size = max(modulus_size, pub_exp_size)
		self.cert_size_target = math.ceil((pubkey_pos + self.modulus_size + self.pub_exp_size) / boundary_align) * boundary_align

# Information related to the key which will be used to sign.
class KeySignatureKind:
	def __init__(self, kind, type_bytes, signature_size):
		self.kind = kind
		self.type_bytes = type_bytes
		self.signature_size = signature_size
		self.tosign_pos = math.ceil((signature_pos + self.signature_size) / boundary_align) * boundary_align
		self.pubkey_pos = self.tosign_pos + pubkey_pos

KeyForSigningKindDict = dict()
KeyForSigningKindDict["rsa2048"] = KeyForSigningKind("rsa2048", rsa2048_type, rsa_2048_size, rsa_2048_pub_exp_dsi_size)
KeyForSigningKindDict["rsa4096"] = KeyForSigningKind("rsa4096", rsa4096_type, rsa_4096_size, rsa_4096_pub_exp_dsi_size)
KeyForSigningKindDict["ecdh"] = KeyForSigningKind("ecdh", ecdh_type, ecdh_size, ecdh_pub_exp_dsi_size)

KeySignatureKindDict = dict()
KeySignatureKindDict["rsa2048"] = KeySignatureKind("rsa2048", sig2048_type, rsa_2048_size)
KeySignatureKindDict["rsa4096"] = KeySignatureKind("rsa4096", sig4096_type, rsa_4096_size)
KeySignatureKindDict["ecdh"] = KeySignatureKind("ecdh", sigecdh_type, ecdh_size)

def getKeySignatureKind(name):
	return KeySignatureKindDict.get(name, None)

def getKeyForSigningKind(name):
	return KeyForSigningKindDict.get(name, None)

def getKeySignatureKindFromBytes(type_bytes):
	for elem in KeySignatureKindDict.keys():
		if are_bytes_same(type_bytes, KeySignatureKindDict[elem].type_bytes):
			return KeySignatureKindDict[elem]
	return None

def getKeyForSigningKindFromBytes(type_bytes):
	for elem in KeyForSigningKindDict.keys():
		if are_bytes_same(type_bytes, KeyForSigningKindDict[elem].type_bytes):
			return KeyForSigningKindDict[elem]
	return None
