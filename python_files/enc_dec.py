from Crypto.PublicKey import RSA
import pyaes
import hashlib
from .nds_rom_header_wii_data import *
from .utils import *
from .signer import Signer
from .key_sig import *

cbc_block_size = 16

sha1_size_bytes = 20
sha1_addon_16_final_bytes = [0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14] # Why? Should check if they are really needed...
sha1_padding_rsa_2048_start = [0x00, 0x01]
sha1_padding_rsa_2048 = sha1_padding_rsa_2048_start + ([0xFF] * (rsa_2048_size - len(sha1_padding_rsa_2048_start) - sha1_size_bytes - len(sha1_addon_16_final_bytes))) + sha1_addon_16_final_bytes

def get_sha1(in_bytes):	
	return hashlib.sha1(bytes(in_bytes)).digest()

# Derives an ID from a string and some bytes (e.g. the NDS ROM title_id).
# Should be a fixed value, so it does not change between builds!
def create_id(type_string, in_bytes):
	return get_sha1(bytes(type_string, 'ascii') + in_bytes)

# Generates a RSA key with pub_exp = 65537.
# Returns pub_exp, modulus, priv_exp.
def generate_rsa_key(bits=2048):
	rsa_key = RSA.generate(bits, e=65537)
	return rsa_key.e, rsa_key.n, rsa_key.d

# Generates a key.
# Currently only supports RSA2048 and RSA4096.
# Returns pub_exp, modulus, priv_exp.
def generate_key(kind = "rsa2048"):
	if kind == "rsa2048":
		return generate_rsa_key(bits=2048)
	if kind == "rsa4096":
		return generate_rsa_key(bits=4096)
	# ECDH not currently supported here!
	return 0, 0, 0

# Tiny helper to change easily how to handle a None common_key.
def sanitize_common_key(common_key):
	if common_key is None:
		common_key = bytes([0] * cbc_block_size)
	return common_key

# Decrypts an encrypted title_key (found in tickets).
# Requires the correct common_key.
# Uses the title_id as an initialization vector.
def decrypt_title_key(title_id, enc_title_key, common_key):
	key_enc_iv = list(title_id) + ([0] * (cbc_block_size - dsi_title_id_size))

	common_key = sanitize_common_key(common_key)

	if common_key is None:
		out = enc_title_key
	else:
		aes = pyaes.AESModeOfOperationCBC(common_key, iv=bytes(key_enc_iv))
		out = aes.decrypt(enc_title_key)

	return out

# Encrypts the title_key (for tickets).
# Requires the correct common_key.
# Uses the title_id as an initialization vector.
def encrypt_title_key(title_id, title_key, common_key):
	key_enc_iv = list(title_id) + ([0] * (cbc_block_size - dsi_title_id_size))

	common_key = sanitize_common_key(common_key)

	if common_key is None:
		out = title_key
	else:
		aes = pyaes.AESModeOfOperationCBC(common_key, iv=bytes(key_enc_iv))
		out = aes.encrypt(title_key)

	return out

# Decrypts an encrypted title_key (found in tickets).
# Uses the NDS ROM to get the title_id.
def decrypt_title_key_nds_rom(nds_rom, enc_title_key, common_key):
	title_id = get_title_id_from_rom(nds_rom)

	return decrypt_title_key(title_id, enc_title_key, common_key)

# Increases position for encryption in TMDs and TADs...
def pad_pos_to_enc(pos):
	len_enc_pos_modulus = pos % cbc_block_size
	if len_enc_pos_modulus != 0:
		pos += cbc_block_size - len_enc_pos_modulus
	return pos

# Pads data for encryption, needed for TMDs and TADs...
def pad_data_to_enc(data):
	len_data_modulus = len(data) % cbc_block_size
	if len_data_modulus != 0:
		data += bytes([0] * (cbc_block_size - len_data_modulus))
	return data

# Turns data into encrypted content.
# Uses the unencrypted title_key as the AES CBC Key.
# content_iv is the index of the content inside the TAD.
def data_to_enc_content(data, title_key, content_iv):

	aes = pyaes.AESModeOfOperationCBC(title_key, iv=bytes(content_iv))
	out = []

	data = pad_data_to_enc(data)

	for i in range(int(len(data) / cbc_block_size)):
		#print("Block " + str(i))
		out += aes.encrypt(data[cbc_block_size * i : cbc_block_size * (i + 1)])

	return out

# Turns data into encrypted content.
def data_to_enc_content_init_iv(data, index, title_key):
	content_iv = [0] * cbc_block_size
	write_int_to_list_of_bytes(content_iv, 0, index, 2)
	return data_to_enc_content(data, title_key, content_iv)

# Turns data into decrypted content.
# Uses the unencrypted title_key as the AES CBC Key.
# content_iv is the index of the content inside the TAD.
def enc_content_to_data(data, title_key, content_iv):

	aes = pyaes.AESModeOfOperationCBC(title_key, iv=bytes(content_iv))
	out = []

	data = pad_data_to_enc(data)

	for i in range(int(len(data) / cbc_block_size)):
		#print("Block " + str(i))
		out += aes.decrypt(data[cbc_block_size * i : cbc_block_size * (i + 1)])

	return out

# Turns data into decrypted content.
def enc_content_to_data_init_iv(enc_content, index, title_key):
	content_iv = [0] * cbc_block_size
	write_int_to_list_of_bytes(content_iv, 0, index, 2)
	return enc_content_to_data(enc_content, title_key, content_iv)

# Turns a NDS ROM into encrypted content.
# content_iv is set to index 0 (as that is always the index of the NDS ROM).
def nds_rom_to_enc_content_init_iv(nds_rom, title_key):
	return data_to_enc_content_init_iv(nds_rom, 0, title_key)

# Returns the properly padded sha1 of to_check.
# Currently only supports RSA2048.
# WAD tickets have slightly different padding...?
def get_padded_sha1(to_check, kind):
	expected_sha1 = bytes([0])
	if kind == "rsa2048":
		expected_sha1 = bytes(sha1_padding_rsa_2048) + get_sha1(to_check)
	# RSA4096 not currently supported here!
	# ECDH not currently supported here!
	return expected_sha1

# Returns whether a signature is valid for a block of data.
# Currently only supports RSA2048 and RSA4096 public key.
def is_signature_valid(data, signer_data):
	key_signature_kind = getKeySignatureKind(signer_data.kind)
	sig_size = key_signature_kind.signature_size
	to_sign_pos = key_signature_kind.tosign_pos

	to_check = data[to_sign_pos:]

	expected_sha1 = get_padded_sha1(to_check, signer_data.kind)

	signature = int.from_bytes(data[signature_pos:signature_pos + sig_size], byteorder='big')

	int_signer_pub_exp = signer_data.int_get_pub_exp()
	int_signer_modulus = signer_data.int_get_modulus()
	if (int_signer_pub_exp is None) or (int_signer_modulus is None):
		hash_signature = signature
	else:
		# ECDH not currently supported here!
		hash_signature = pow(signature, int_signer_pub_exp, int_signer_modulus)

	hash_signature = hash_signature.to_bytes(sig_size, 'big')
	if hash_signature == expected_sha1:
		return True

	if hash_signature[-sha1_size_bytes:] == expected_sha1[-sha1_size_bytes:]:
		print("INFO: Hash bytes match, but not preamble.")
		#print("0x" + bytes_list_to_hex_str(hash_signature[:-sha1_size_bytes], spacer=", 0x"))
		return True

	return False

# Signs a block of data.
# Currently only supports RSA2048 and RSA4096 private key.
def sign_data(data, signer_data):
	key_signature_kind = getKeySignatureKind(signer_data.kind)
	sig_type = key_signature_kind.type_bytes
	sig_size = key_signature_kind.signature_size
	to_sign_pos = key_signature_kind.tosign_pos

	to_check = data[to_sign_pos:]

	expected_sha1 = get_padded_sha1(to_check, signer_data.kind)

	int_signer_priv_exp = signer_data.int_get_priv_exp()
	int_signer_modulus = signer_data.int_get_modulus()
	if (int_signer_priv_exp is None) or (int_signer_modulus is None):
		signature_bytes = expected_sha1
	else:
		# ECDH not currently supported here!
		signature = int.from_bytes(expected_sha1, byteorder='big')
		hash_signature = pow(signature, int_signer_priv_exp, int_signer_modulus)

		signature_bytes = hash_signature.to_bytes(sig_size, 'big')

	out = list(data)
	write_bytes_to_list_of_bytes(out, 0, sig_type)
	write_bytes_to_list_of_bytes(out, signature_pos, signature_bytes)

	return out
