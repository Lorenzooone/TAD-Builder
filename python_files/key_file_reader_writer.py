from .key_sig import getKeyForSigningKind
from .file_io import *

def read_key_file_value(lines, start_index):
	size_value = int(lines[start_index].strip())

	list_bytes = []
	hex_to_read = lines[start_index + 1].strip().split()
	for i in range(size_value):
		list_bytes += [int(hex_to_read[i], 16)]

	return bytes(list_bytes)

# Obtains the RSA key from an input .key file.
def read_key_file(filename):
	lines = read_file_lines(filename)
	if lines is None:
		return "", None, None, None

	index_to_check = 0
	while lines[index_to_check].strip() == "":
		index_to_check += 1

	kind = ""
	read_kind_obj = getKeyForSigningKind(lines[index_to_check].strip())
	if read_kind_obj is not None:
		kind = read_kind_obj.kind
		index_to_check += 1

	pub_exp = read_key_file_value(lines, index_to_check)
	modulus = read_key_file_value(lines, index_to_check + 2)
	priv_exp = read_key_file_value(lines, index_to_check + 4)

	return kind, pub_exp, modulus, priv_exp

def key_value_to_string(value, size):
	if len(value) == 0:
		return "1\n00"

	while (value[0] == 0) and (len(value) > 1):
		value = value[1:]

	out_str = str(len(value)) + "\n"

	for i in range(len(value)):
		out_str +=  ("%02x" % value[i]) + " "

	return out_str

# Writes the RSA key to an output .key file.
def write_key_file(filename, pub_exp, modulus, priv_exp, key_kind="rsa2048"):
	key_for_signing_kind = getKeyForSigningKind(key_kind)
	if key_for_signing_kind is None:
		return

	size_keys = key_for_signing_kind.key_size

	out_total = key_kind + "\n"

	out_total += key_value_to_string(pub_exp, size_keys) + "\n"
	out_total += key_value_to_string(modulus, size_keys) + "\n"
	out_total += key_value_to_string(priv_exp, size_keys) + "\n"

	write_file_lines(filename, out_total)
