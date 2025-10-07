from .enc_dec import get_sha1, create_id, sha1_size_bytes
from .nds_rom_header import *
from .utils import *

cmd_size = 0x24

content_id_pos = 0
content_id_size = 4
content_index_pos = 4
content_index_size = 2
content_type_pos = 6
content_type_size = 2
content_size_pos = 8
content_size_size = 8
content_sha1_pos = 16
content_sha1_size = sha1_size_bytes

# Creates the CMD (Content MetaData) for the actual content.
# Generic function, which is not DSi-specific.
def cmd_create(content_id, index, type_content, decrypted_content):
	cmd = [0] * cmd_size

	write_bytes_to_list_of_bytes(cmd, content_id_pos, content_id)

	write_int_to_list_of_bytes(cmd, content_index_pos, index, content_index_size)

	write_bytes_to_list_of_bytes(cmd, content_type_pos, type_content)

	write_int_to_list_of_bytes(cmd, content_size_pos, len(decrypted_content), content_size_size)

	sha1_to_set = get_sha1(decrypted_content)
	write_bytes_to_list_of_bytes(cmd, content_sha1_pos, sha1_to_set)

	return cmd

class DataCMD:
	content_id_specs_str = "CONTENT ID"
	type_content_specs_str = "CONTENT TYPE"
	is_boot_specs_str = "CONTENT BOOT"
	content_filename_specs_str = "CONTENT FILENAME"

	def __init__(self, content_id=None, content_index=None, type_content=None, content_size=None, is_boot_content=False, decrypted_content=None, content_filename=None):
		self.content_id = content_id
		self.content_index = content_index
		self.type_content = type_content
		self.content_size = content_size
		self.is_boot_content = is_boot_content
		self.decrypted_content = decrypted_content
		if content_filename is None:
			self.content_filename = bytes_list_to_hex_str(self.content_id, spacer="") + "_unenc.app"
		else:
			self.content_filename = content_filename

	def get_boot_content_str(self):
		if self.is_boot_content == True:
			return "1"
		return "0"

	def get_content_filename(self, file_preamble=""):
		return file_preamble + self.content_filename

	def specs_str(self, preamble, file_preamble = ""):
		out_str = ""
		out_str += preamble + " " + DataCMD.content_id_specs_str + ": " + bytes_list_to_hex_str(self.content_id) + "\n"
		out_str += preamble + " " + DataCMD.type_content_specs_str + ": " + bytes_list_to_hex_str(self.type_content) + "\n"
		out_str += preamble + " " + DataCMD.is_boot_specs_str + ": " + self.get_boot_content_str() + "\n"
		out_str += preamble + " " + DataCMD.content_filename_specs_str + ": " + self.get_content_filename(file_preamble=file_preamble) + "\n"

		return out_str
		

# Reads the data of a cmd. Returns the content_id, the content_index,
# the type_content, the content_size and whether the content is boot or not.
# As a DataCMD object.
# Returns None in case of error.
def read_cmd(data_start, is_boot_content):
	if len(data_start) < cmd_size:
		return None

	content_id = data_start[content_id_pos:content_id_pos + content_id_size]

	content_index = read_int_from_list_of_bytes(data_start, content_index_pos, content_index_size)

	type_content = data_start[content_type_pos:content_type_pos + content_type_size]

	content_size = read_int_from_list_of_bytes(data_start, content_size_pos, content_size_size)

	return DataCMD(content_id=content_id, content_index=content_index, type_content=type_content, content_size=content_size, is_boot_content=is_boot_content)

# Creates the CMD for a DSi file.
# In theory it should also support non-ROM files.
def cmd_create_dsi(content_base_id, index, decrypted_content):
	content_id = create_id("content" + str(index), content_base_id)[:content_id_size]
	return cmd_create(content_id, index, [0, 1], decrypted_content)

# Creates the CMD for a DSi ROM.
def cmd_get_content_base_id_dsi_rom(uncrypted_nds_rom):
	return get_title_id_from_rom(uncrypted_nds_rom)
