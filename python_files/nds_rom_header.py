
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

boundary_align = 0x40

# Returns the title_id, which is normally stored reversed in the DSi header.
def get_title_id_from_rom(nds_rom):
	title_id = list(nds_rom[nds_rom_location_dsi_header_reverse_title:nds_rom_location_dsi_header_reverse_title + dsi_title_id_size])
	title_id.reverse()
	title_id = bytes(title_id)
	return title_id
	
