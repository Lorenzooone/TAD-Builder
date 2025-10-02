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

# Creates the CMD for a DSi file.
# In theory it should also support non-ROM files.
def cmd_create_dsi(content_base_id, decrypted_content):
	content_id = create_id("content" + str(0), content_base_id)[:content_id_size]
	return cmd_create(content_id, 0, [0, 1], decrypted_content)

# Creates the CMD for a DSi ROM.
def cmd_create_dsi_rom(uncrypted_nds_rom):
	return cmd_create_dsi(get_title_id_from_rom(uncrypted_nds_rom), uncrypted_nds_rom)
