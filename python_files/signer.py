from .key_sig import getKeyForSigningKind

class Signer:
	def convert_to_bytes(value, is_pub_exp, kind):
		if value is None:
			return None
		if isinstance(value, int):
			signing_key_kind = getKeyForSigningKind(kind)
			if signing_key_kind is None:
				return None
			target_size = signing_key_kind.modulus_size
			if is_pub_exp:
				target_size = signing_key_kind.pub_exp_size
			return value.to_bytes(target_size, 'big')
		return bytes(value)

	def __init__(self, name="", pub_exp=None, modulus=None, priv_exp=None, kind="rsa2048"):
		if (kind is None) or (kind == ""):
			# Have a default...
			kind = "rsa2048"
		self.name = name
		self.pub_exp = Signer.convert_to_bytes(pub_exp, True, kind)
		self.modulus = Signer.convert_to_bytes(modulus, False, kind)
		self.priv_exp = Signer.convert_to_bytes(priv_exp, False, kind)
		self.kind = kind

	def get_name_bytes(self, signer_size):
		out = self.name
		if len(out) > (signer_size - 1):
			out = out[:signer_size - 1]
		return bytes(out, 'ascii')

	def int_get_pub_exp(self):
		if self.pub_exp is None:
			return None
		return int.from_bytes(self.pub_exp, byteorder='big')

	def int_get_modulus(self):
		if self.modulus is None:
			return None
		return int.from_bytes(self.modulus, byteorder='big')

	def int_get_priv_exp(self):
		if self.priv_exp is None:
			return None
		return int.from_bytes(self.priv_exp, byteorder='big')

	def can_be_pub_compatible(self):
		if self.modulus is None:
			return False
		if self.pub_exp is None:
			return False
		return True

	def is_pub_compatible(self, other):
		if not self.can_be_pub_compatible():
			return False
		if not other.can_be_pub_compatible():
			return False

		if self.int_get_modulus() != other.int_get_modulus():
			return False
		if self.int_get_pub_exp() != other.int_get_pub_exp():
			return False
		return True

def find_signer_in_list(signer_data_list, signer_data_target):
	for signer_data_elem in signer_data_list:
		if signer_data_target.is_pub_compatible(signer_data_elem):
			return signer_data_elem
	return None

def fill_signer_data_name_with_list(signer_data_list, signer_data_target, default_name, not_found_error_msg):
	if signer_data_target.name != "":
		return
	signer_data_target.name = default_name
	signer_data_elem = find_signer_in_list(signer_data_list, signer_data_target)
	if signer_data_elem is None:
		if signer_data_target.can_be_pub_compatible():
			print(not_found_error_msg)
	else:
		signer_data_target.name = signer_data_elem.name
