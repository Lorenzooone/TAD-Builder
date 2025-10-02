def write_bytes_to_list_of_bytes(target, offset, value):
	for i in range(len(value)):
		target[offset + i] = value[i]

def write_int_to_list_of_bytes(target, offset, value, size):
	return write_bytes_to_list_of_bytes(target, offset, value.to_bytes(size, 'big'))

def are_bytes_same(data, cmp_data):
	if len(data) != len(cmp_data):
		return False

	for i in range(len(data)):
		if data[i] != cmp_data[i]:
			return False

	return True
