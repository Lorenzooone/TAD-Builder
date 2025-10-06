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
	if len(bytes_list) < 1:
		return out_str

	format_string_out = "%02x"
	out_str += (format_string_out % bytes_list[0])
	for i in range(1, len(bytes_list)):
		out_str +=  spacer + (format_string_out % bytes_list[i])

	return out_str

def hex_str_to_bytes_list(hex_str, num_values):
	list_bytes = []
	hex_to_read = hex_str.strip().split()
	for i in range(num_values):
		list_bytes += [int(hex_to_read[i], 16)]

	return bytes(list_bytes)

def are_bytes_same(data, cmp_data):
	if len(data) != len(cmp_data):
		return False

	for i in range(len(data)):
		if data[i] != cmp_data[i]:
			return False

	return True
