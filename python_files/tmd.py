from .enc_dec import sign_data, create_id, encrypt_title_key, decrypt_title_key
from .cmd import cmd_create_dsi_rom
from .nds_rom_header import *
from .utils import *
from .key_sig import getKeySignatureKind

tmd_size_base = 0xA4

signer_offset = 0
signer_size = 0x40
title_id_offset = 0x4C
title_type_offset = 0x54
title_type_size = 4
group_id_offset = 0x58
public_sav_size_offset = 0x5A
private_sav_size_offset = 0x5E
parental_control_offset = 0x6A
access_rights_offset = 0x98
access_rights_size = 4
title_version_offset = 0x9C
num_contents_offset = 0x9E
num_contents_size = 2
boot_content_offset = 0xA0
boot_content_size = 2

# Creates the initial part of a TMD (Title MetaData). Before any CMD (Content MetaData).
# Returns an empty list in case of an error.
def tmd_create_base(title_id, title_version, group_id, pubic_sav_size, private_sav_size, parental_control, num_contents, boot_content, signer_data):
	key_signature_kind = getKeySignatureKind(signer_data.kind)
	if key_signature_kind is None:
		print("Issue finding signature key")
		return []
	data_pos = key_signature_kind.tosign_pos
	tmd_size = data_pos + tmd_size_base

	tmd = [0] * tmd_size

	if num_contents <= 0:
		print("TMD num contents error!")
		return []

	if boot_content >= num_contents:
		print("TMD boot content error!")
		return []


	signer_name_bytes = signer_data.get_name_bytes(signer_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + signer_offset, signer_name_bytes)

	write_bytes_to_list_of_bytes(tmd, data_pos + title_id_offset, title_id)

	write_int_to_list_of_bytes(tmd, data_pos + title_type_offset, 0, title_type_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + group_id_offset, group_id)

	write_bytes_to_list_of_bytes(tmd, data_pos + public_sav_size_offset, pubic_sav_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + private_sav_size_offset, private_sav_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + parental_control_offset, parental_control)

	write_int_to_list_of_bytes(tmd, data_pos + access_rights_offset, 0, access_rights_size)

	write_bytes_to_list_of_bytes(tmd, data_pos + title_version_offset, title_version)

	write_int_to_list_of_bytes(tmd, data_pos + num_contents_offset, num_contents, num_contents_size)

	write_int_to_list_of_bytes(tmd, data_pos + boot_content_offset, boot_content, boot_content_size)

	return tmd

# Creates the TMD for a NDS ROM.
# Extracts various data needed to create the TMD from the NDS ROM,
# and then calls tmd_create_base with it.
# Also appends the single CMD of the NDS ROM.
# Uses the signer and the private key to sign the TMD + CMD.
def tmd_create_rom(nds_rom, signer_data):
	title_id = get_title_id_from_rom(nds_rom)
	title_version = nds_rom[nds_rom_location_version:nds_rom_location_version + dsi_version_size]
	group_id = nds_rom[nds_rom_location_group_id:nds_rom_location_group_id + nds_groud_id_size]
	pubic_sav_size = nds_rom[dsi_rom_location_public_sav_size:dsi_rom_location_public_sav_size + dsi_public_sav_size_size]
	private_sav_size = nds_rom[dsi_rom_location_private_sav_size:dsi_rom_location_private_sav_size + dsi_private_sav_size_size]
	parental_control = nds_rom[dsi_rom_location_parental_control:dsi_rom_location_parental_control + dsi_parental_control_size]

	tmd = tmd_create_base(title_id, title_version, group_id, pubic_sav_size, private_sav_size, parental_control, 1, 0, signer_data)

	tmd += cmd_create_dsi_rom(nds_rom)

	tmd = sign_data(bytes(tmd), signer_data)

	return tmd
