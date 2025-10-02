def read_file_lines(filename, accept_dash=True, ret_none=True):
	lines = None
	if not ret_none:
		lines = []

	if accept_dash and filename == "-":
		return lines

	try:
		with open(filename) as f:
			lines = f.read().split('\n')
	except:
		print("Error reading lines of file! " + filename)
	return lines

def read_file_bytes(filename, accept_dash=True, ret_none=True):
	data = None
	if not ret_none:
		data = []

	if accept_dash and filename == "-":
		return data

	try:
		with open(filename, "rb") as f:
			data = f.read()
	except:
		print("Error reading bytes of file! " + filename)
	return data

def write_file_lines(filename, lines, accept_dash=True):
	if (lines is None) or (len(lines) == 0) or (accept_dash and filename == "-"):
		return

	try:
		with open(filename, "w") as f:
			f.write(lines)
	except:
		print("Error writing lines to file! " + filename)

def write_file_bytes(filename, data, accept_dash=True):
	if (data is None) or (len(data) == 0) or (accept_dash and filename == "-"):
		return

	try:
		with open(filename, "wb") as f:
			f.write(bytes(data))
	except:
		print("Error writing bytes to file! " + filename)
