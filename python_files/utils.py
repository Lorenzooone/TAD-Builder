def write_bytes_to_list_of_bytes(target, offset, value):
	for i in range(len(value)):
		target[offset + i] = value[i]

def write_int_to_list_of_bytes(target, offset, value, size):
	return write_bytes_to_list_of_bytes(target, offset, value.to_bytes(size, 'big'))

def read_int_from_list_of_bytes(target, offset, size):
	return int.from_bytes(bytes(target[offset: offset + size]), byteorder='big')

def read_string_from_list_of_bytes(target, offset, size):
	return target[offset:offset + size].decode("ascii").replace("\x00", "")

def bytes_list_to_hex_str(bytes_list, spacer=" "):
	out_str = ""
	if bytes_list is None:
		return out_str
	if len(bytes_list) < 1:
		return out_str

	format_string_out = "%02x"
	out_str += (format_string_out % bytes_list[0])
	for i in range(1, len(bytes_list)):
		out_str +=  spacer + (format_string_out % bytes_list[i])

	return out_str

def hex_str_to_bytes_list(hex_str, num_values):
	list_bytes = []

	if hex_str is None:
		return bytes(list_bytes)

	hex_to_read = hex_str.strip().split()
	for i in range(num_values):
		list_bytes += [int(hex_to_read[i], 16)]

	return bytes(list_bytes)

def hex_str_to_bytes_list_no_spaces(hex_str, num_values):
	list_bytes = []

	if hex_str is None:
		return None

	if hex_str == "-" or hex_str == "":
		return None

	if len(hex_str) < (num_values * 2):
		return None

	hex_to_read = hex_str.strip()
	for i in range(num_values):
		list_bytes += [int(hex_to_read[i * 2:(i + 1) * 2], 16)]

	return bytes(list_bytes)

def int_str_to_int(int_str):
	if int_str is None:
		return None

	if int_str == "-" or int_str == "":
		return None

	return int(int_str)

def are_bytes_same(data, cmp_data):
	if (data is None) and (cmp_data is None):
		return True
	if data is None:
		return False
	if cmp_data is None:
		return False

	if len(data) != len(cmp_data):
		return False

	for i in range(len(data)):
		if data[i] != cmp_data[i]:
			return False

	return True

def index_of_string_start_in_list(string_list, wanted_start):
	for i in range(len(string_list)):
		if string_list[i].startswith(wanted_start):
			return i
	return None

def read_string_of_string_start_in_list(string_list, wanted_start, extra=": "):
	ret = index_of_string_start_in_list(string_list, wanted_start + extra)
	if ret is None:
		return None

	manip_string = string_list[ret][len(wanted_start + extra):].strip()
	return manip_string

def read_int_of_string_start_in_list(string_list, wanted_start, extra=": "):
	ret = read_string_of_string_start_in_list(string_list, wanted_start, extra=extra)
	if ret is None:
		return None

	return int(ret)

def read_bool_of_string_start_in_list(string_list, wanted_start, extra=": "):
	ret = read_string_of_string_start_in_list(string_list, wanted_start, extra=extra)
	if ret is None:
		return None

	if ret == "0":
		return False
	return True

def read_bytes_of_string_start_in_list(string_list, wanted_start, num_bytes, extra=": "):
	ret = read_string_of_string_start_in_list(string_list, wanted_start, extra=extra)
	if ret is None:
		return None

	return hex_str_to_bytes_list(ret, num_bytes)
