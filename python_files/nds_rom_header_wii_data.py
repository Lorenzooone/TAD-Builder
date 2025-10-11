
dsi_title_is_data = [0, 3, 0, 0xF]

nds_rom_location_dsi_header_reverse_title = 0x230
dsi_title_id_size = 8
nds_rom_location_version = 0x1E
dsi_version_size = 2
nds_rom_location_group_id = 0x10
nds_groud_id_size = 2
dsi_rom_location_public_sav_size = 0x238
dsi_public_sav_size_size = 4
dsi_rom_location_private_sav_size = 0x23C
dsi_private_sav_size_size = 4
dsi_rom_location_parental_control = 0x2F0
dsi_parental_control_size = 0x10
dsi_rom_location_size = 0x210
dsi_rom_size_size = 8

sys_version_size = 8
parental_control_full_access_byte = 0x80
region_free_wad_region = 3
# I think this is a data title?! Maybe not though?!
wii_title_is_data = [0, 1, 0, 5]
#wii_title_is_data = [0, 1, 0, 8]

boundary_align = 0x40

def pad_pos_to_boundary_align(pos):
	len_enc_pos_modulus = pos % boundary_align
	if len_enc_pos_modulus != 0:
		pos += boundary_align - len_enc_pos_modulus
	return pos

def pad_data_to_boundary_align(data):
	len_data_modulus = len(data) % boundary_align
	if len_data_modulus != 0:
		data += bytes([0] * (boundary_align - len_data_modulus))
	return data

# Returns the title_id, which is normally stored reversed in the DSi header.
def get_title_id_from_rom(nds_rom):
	title_id = list(nds_rom[nds_rom_location_dsi_header_reverse_title:nds_rom_location_dsi_header_reverse_title + dsi_title_id_size])
	title_id.reverse()
	title_id = bytes(title_id)
	return title_id

class NDSRomHeaderTADInfo:
	def __init__(self, nds_rom):
		self.title_id = get_title_id_from_rom(nds_rom)
		self.title_version = nds_rom[nds_rom_location_version:nds_rom_location_version + dsi_version_size]
		self.group_id = nds_rom[nds_rom_location_group_id:nds_rom_location_group_id + nds_groud_id_size]
		self.public_sav_size = nds_rom[dsi_rom_location_public_sav_size:dsi_rom_location_public_sav_size + dsi_public_sav_size_size]
		self.private_sav_size = nds_rom[dsi_rom_location_private_sav_size:dsi_rom_location_private_sav_size + dsi_private_sav_size_size]
		self.parental_control = nds_rom[dsi_rom_location_parental_control:dsi_rom_location_parental_control + dsi_parental_control_size]
