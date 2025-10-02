from .enc_dec import *
from .utils import *
from .signer import Signer
from .key_sig import pubkey_pos, getKeySignatureKind, getKeyForSigningKind, getKeySignatureKindFromBytes, getKeyForSigningKindFromBytes

signer_offset = 0
signer_size = 0x40
key_type_offset = 0x40
key_name_offset = 0x44
key_id_offset = 0x84
key_id_size = 4
key_offset = pubkey_pos

# Creates the a certificate, plus a key.
# Self signing TMDs and tickets does not seem to work, for some reason...
# Can return an empty list in case of errors.
def cert_create(name, signer_data, target_key="rsa2048"):
	key_signature_kind = getKeySignatureKind(signer_data.kind)
	if key_signature_kind is None:
		print("Issue finding signature key")
		return None
	data_pos = key_signature_kind.tosign_pos

	key_for_signing_kind = getKeyForSigningKind(target_key)
	if key_for_signing_kind is None:
		print("Issue finding new signing key")
		return None
	cert_after_size = key_for_signing_kind.cert_size_target
	target_key_modulus_size = key_for_signing_kind.modulus_size
	target_key_pub_exp_size = key_for_signing_kind.pub_exp_size
	key_type = key_for_signing_kind.type_bytes

	cert_size = cert_after_size + data_pos

	cert = [0] * cert_size

	total_name = signer_data.name + "-" + name
	if len(total_name) > (signer_size - 1):
		print("Name too long!")
		return None

	signer_name_bytes = signer_data.get_name_bytes(signer_size)

	write_bytes_to_list_of_bytes(cert, data_pos + signer_offset, signer_name_bytes)

	write_bytes_to_list_of_bytes(cert, data_pos + key_type_offset, key_type)

	name = bytes(name, 'ascii')
	write_bytes_to_list_of_bytes(cert, data_pos + key_name_offset, name)

	key_id = create_id("cert", bytes(total_name, 'ascii'))[:key_id_size]
	write_bytes_to_list_of_bytes(cert, data_pos + key_id_offset, key_id)

	out_pub_exp, out_modulus, out_priv_exp = generate_key(kind=target_key)

	write_int_to_list_of_bytes(cert, data_pos + key_offset, out_modulus, target_key_modulus_size)

	write_int_to_list_of_bytes(cert, data_pos + key_offset + target_key_modulus_size, out_pub_exp, target_key_pub_exp_size)

	cert = sign_data(bytes(cert), signer_data)

	return cert, Signer(name=total_name, pub_exp=out_pub_exp, modulus=out_modulus, priv_exp=out_priv_exp, kind=target_key)

# Reads a cert and returns the name, the modulus and the pub_exp,
# plus the unused data. Returns None in case of error.
def read_cert(data_start):
	if len(data_start) < signature_pos:
		return None

	sig_type_bytes = data_start[:signature_pos]
	key_signature_kind = getKeySignatureKindFromBytes(sig_type_bytes)

	if key_signature_kind is None:
		return None

	data_pos = key_signature_kind.tosign_pos

	if len(data_start) < key_signature_kind.pubkey_pos:
		return None

	if data_start[data_pos + signer_offset + signer_size - 1] != 0:
		return None

	if data_start[data_pos + key_name_offset + signer_size - 1] != 0:
		return None

	signer_name = data_start[data_pos + signer_offset:data_pos + signer_offset + signer_size].decode("ascii").replace("\x00", "")

	key_name = data_start[data_pos + key_name_offset:data_pos + key_name_offset + signer_size].decode("ascii").replace("\x00", "")

	total_name = signer_name + "-" + key_name

	if len(total_name) > (signer_size - 1):
		return None

	key_type_bytes = data_start[data_pos + key_type_offset:data_pos + key_type_offset + key_type_size]

	key_id = data_start[data_pos + key_id_offset:data_pos + key_id_offset + key_id_size] # Unused for this...

	key_for_signing_kind = getKeyForSigningKindFromBytes(key_type_bytes)

	if key_for_signing_kind is None:
		return None

	if len(data_start) < (data_pos + key_for_signing_kind.cert_size_target):
		return None

	modulus = bytes(data_start[key_signature_kind.pubkey_pos:key_signature_kind.pubkey_pos + key_for_signing_kind.modulus_size])
	pub_exp = bytes(data_start[key_signature_kind.pubkey_pos + key_for_signing_kind.modulus_size:key_signature_kind.pubkey_pos + key_for_signing_kind.modulus_size + key_for_signing_kind.pub_exp_size])

	return Signer(name=total_name, modulus=modulus, pub_exp=pub_exp, kind = key_for_signing_kind.kind), data_start[data_pos + key_for_signing_kind.cert_size_target:]

# Creates a list of available cert with their name, modulus, and pub_exp
def read_certchain(cert_chain):
	out = []
	in_cert_chain = cert_chain

	while len(in_cert_chain) > 0:
		result = read_cert(in_cert_chain)
		if result is None:
			break
		out += [result[0]]
		in_cert_chain = result[1]

	return out

# Returns whether a signature is valid for a block of data.
# Gets the public key from a certificate.
def is_signature_valid_cert(data, cert):
	out = read_cert(cert)

	if out is None:
		return False

	signer_data = out[0]

	return is_signature_valid(data, signer_data)
