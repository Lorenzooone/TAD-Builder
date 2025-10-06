from .key_sig import getKeyForSigningKind
from .file_io import *
from .utils import *

def read_key_file_value(lines, start_index):
	size_value = int(lines[start_index].strip())

	return hex_str_to_bytes_list(lines[start_index + 1], size_value)

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

def key_value_to_string(value):
	if len(value) == 0:
		return "1\n00"

	while (value[0] == 0) and (len(value) > 1):
		value = value[1:]

	out_str = str(len(value)) + "\n"
	return out_str + bytes_list_to_hex_str(value)

# Writes the RSA key to an output .key file.
def write_key_file(filename, pub_exp, modulus, priv_exp, key_kind="rsa2048"):
	key_for_signing_kind = getKeyForSigningKind(key_kind)
	if key_for_signing_kind is None:
		return

	size_keys = key_for_signing_kind.key_size

	out_total = key_kind + "\n"

	out_total += key_value_to_string(pub_exp) + "\n"
	out_total += key_value_to_string(modulus) + "\n"
	out_total += key_value_to_string(priv_exp) + "\n"

	write_file_lines(filename, out_total)
