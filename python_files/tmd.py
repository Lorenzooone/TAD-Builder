from .enc_dec import sign_data, create_id, encrypt_title_key, decrypt_title_key, pad_data_to_enc, signature_pos
from .cmd import cmd_create_all, read_cmd, cmd_size
from .nds_rom_header_wii_data import *
from .utils import *
from .key_sig import getKeySignatureKind, getKeySignatureKindFromBytes

tmd_size_base = 0xA4

signer_offset = 0
signer_size = 0x40
sys_version_offset = 0x44
title_id_offset = 0x4C
title_type_offset = 0x54
title_type_size = 4
group_id_offset = 0x58
tad_public_sav_size_offset = 0x5A
tad_private_sav_size_offset = 0x5E
tad_parental_control_offset = 0x6A
wad_region_offset = 0x5C
wad_region_size = 2
wad_parental_control_offset = 0x5E
wad_ipc_mask_offset = 0x7A
wad_ipc_mask_size = 12
access_rights_offset = 0x98
access_rights_size = 4
title_version_offset = 0x9C
num_contents_offset = 0x9E
num_contents_size = 2
boot_content_offset = 0xA0
boot_content_size = 2

# Creates the initial part of a TMD (Title MetaData). Before any CMD (Content MetaData).
# Returns an empty list in case of an error.
def tmd_create_base(title_id, title_version, group_id, title_type, pubic_sav_size, private_sav_size, parental_control, sys_version, signer_data, is_tad):
	key_signature_kind = getKeySignatureKind(signer_data.kind)
	if key_signature_kind is None:
		print("Issue finding signature key")
		return []
	data_pos = key_signature_kind.tosign_pos
	tmd_size = data_pos + tmd_size_base

	tmd = [0] * tmd_size

	signer_name_bytes = signer_data.get_name_bytes(signer_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + signer_offset, signer_name_bytes)

	if sys_version is None:
		sys_version = bytes([0] * sys_version_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + sys_version_offset, sys_version)

	write_bytes_to_list_of_bytes(tmd, data_pos + title_id_offset, title_id)

	write_int_to_list_of_bytes(tmd, data_pos + title_type_offset, title_type, title_type_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + group_id_offset, group_id)

	if parental_control is None:
		parental_control = bytes([parental_control_full_access_byte] * dsi_parental_control_size)

	if is_tad:
		write_bytes_to_list_of_bytes(tmd, data_pos + tad_public_sav_size_offset, pubic_sav_size)

		write_bytes_to_list_of_bytes(tmd, data_pos + tad_private_sav_size_offset, private_sav_size)

		write_bytes_to_list_of_bytes(tmd, data_pos + tad_parental_control_offset, parental_control)
	else:
		write_int_to_list_of_bytes(tmd, data_pos + wad_region_offset, region_free_wad_region, wad_region_size)

		write_bytes_to_list_of_bytes(tmd, data_pos + wad_parental_control_offset, parental_control)

	write_int_to_list_of_bytes(tmd, data_pos + access_rights_offset, 0, access_rights_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + title_version_offset, title_version)

	return tmd

# Completes the creation of a TMD by appending CMDs.
def tmd_add_content_multiple(tmd, data_list, boot_content_index, content_base_id, signer_data, cmds_list):
	key_signature_kind = getKeySignatureKind(signer_data.kind)
	if key_signature_kind is None:
		print("Issue finding signature key")
		return []
	data_pos = key_signature_kind.tosign_pos

	num_contents = len(data_list)

	if (cmds_list is not None) and (len(cmds_list) != num_contents):
		print("cmds_list information has issues... Discarding it!")
		cmds_list = None

	if num_contents <= 0:
		print("TMD num contents error!")
		return []

	if boot_content_index >= num_contents:
		print("TMD boot content error!")
		return []

	write_int_to_list_of_bytes(tmd, data_pos + num_contents_offset, num_contents, num_contents_size)

	write_int_to_list_of_bytes(tmd, data_pos + boot_content_offset, boot_content_index, boot_content_size)

	content_id_str_list = []
	for i in range(num_contents):
		corresponding_cmd = None
		if cmds_list is not None:
			corresponding_cmd = cmds_list[i]
		tmd += cmd_create_all(content_base_id, i, data_list[i], content_id_str_list, corresponding_cmd)

	return tmd

def pad_data_list_for_tmd(data_list):
	for i in range(len(data_list)):
		data_list[i] = pad_data_to_enc(data_list[i])
	return data_list

class DataTMD:
	def __init__(self, title_id=None, title_version=None, sys_version = None, title_type=None, group_id=None, contents=None, signer_name="TMD"):
		self.title_id = title_id
		self.title_version = title_version
		self.sys_version = sys_version
		self.title_type = title_type
		self.group_id = group_id
		self.cmds = contents
		self.signer_name = signer_name

# Reads a ticket and returns title_id, title_type, group_id, title_version,
# cmd_data for all contents (see read_cmd) and signer_name.
# As a DataTMD object.
# Returns None in case of error.
def read_tmd(data_start):
	if len(data_start) < signature_pos:
		return None

	sig_type_bytes = data_start[:signature_pos]
	key_signature_kind = getKeySignatureKindFromBytes(sig_type_bytes)

	if key_signature_kind is None:
		return None

	data_pos = key_signature_kind.tosign_pos

	if len(data_start) < (data_pos + tmd_size_base):
		return None

	sys_version = data_start[data_pos + sys_version_offset:data_pos + sys_version_offset + sys_version_size]
	title_id = data_start[data_pos + title_id_offset:data_pos + title_id_offset + dsi_title_id_size]
	title_type = read_int_from_list_of_bytes(data_start, data_pos + title_type_offset, title_type_size)
	group_id = data_start[data_pos + group_id_offset:data_pos + group_id_offset + nds_groud_id_size]
	title_version = data_start[data_pos + title_version_offset:data_pos + title_version_offset + dsi_version_size]
	signer_name = read_string_from_list_of_bytes(data_start, data_pos + signer_offset, signer_size)

	num_contents = read_int_from_list_of_bytes(data_start, data_pos + num_contents_offset, num_contents_size)
	boot_index = read_int_from_list_of_bytes(data_start, data_pos + boot_content_offset, boot_content_size)

	contents = []
	for i in range(num_contents):
		cmd_pos = data_pos + tmd_size_base + (cmd_size * i)
		if len(data_start) < cmd_pos:
			break
		contents += [read_cmd(data_start[cmd_pos:], boot_index == i)]

	return DataTMD(title_id=title_id, title_version=title_version, sys_version=sys_version, title_type=title_type, group_id=group_id, contents=contents, signer_name=signer_name)

# Creates the TMD.
# Supports multiple contents.
# Calls tmd_create_base with the needed data.
# Uses the signer and the private key to sign the TMD + CMD.
def tmd_create_all(data_list, boot_content_index, title_id, title_version, title_type, group_id, public_sav_size, private_sav_size, parental_control, sys_version, signer_data, is_tad, cmds_list):
	data_list = pad_data_list_for_tmd(data_list)

	tmd = tmd_create_base(title_id, title_version, group_id, title_type, public_sav_size, private_sav_size, parental_control, sys_version, signer_data, is_tad)

	tmd = tmd_add_content_multiple(tmd, data_list, boot_content_index, title_id, signer_data, cmds_list)

	tmd = sign_data(bytes(tmd), signer_data)

	return tmd

# Creates the TMD for a NDS ROM.
# Supports multiple contents.
# Extracts various data needed to create the TMD from the NDS ROM,
# and then calls tmd_create_base with it.
# Also appends the single CMD of the NDS ROM.
# Uses the signer and the private key to sign the TMD + CMD.
def tmd_create_rom(data_list, nds_rom_index, signer_data):
	nds_rom = data_list[nds_rom_index]

	nds_rom_header_data = NDSRomHeaderTADInfo(nds_rom)

	return tmd_create_all(data_list, nds_rom_index, nds_rom_header_data.title_id, nds_rom_header_data.title_version, 0, nds_rom_header_data.group_id, nds_rom_header_data.public_sav_size, nds_rom_header_data.private_sav_size, nds_rom_header_data.parental_control, None, signer_data, True, None)

# Creates the TMD for a NDS ROM.
# Supports only one content.
# Extracts various data needed to create the TMD from the NDS ROM,
# and then calls tmd_create_base with it.
# Also appends the single CMD of the NDS ROM.
# Uses the signer and the private key to sign the TMD + CMD.
def tmd_create_solo_nds_rom(nds_rom, signer_data):
	return tmd_create_rom([nds_rom], 0, signer_data)
