from .enc_dec import data_to_enc_content_init_iv, is_signature_valid, pad_pos_to_enc, enc_content_to_data_init_iv
from .ticket import ticket_create_rom, read_ticket, ticket_create_all
from .tmd import tmd_create_rom, pad_data_list_for_tmd, read_tmd, sys_version_size, tmd_create_all
from .cmd import DataCMD
from .nds_rom_header_wii_data import *
from .utils import *
from .cert import read_certchain
from .signer import fill_signer_data_name_with_list, find_signer_in_list_by_name

tad_header_size = 0x20
tad_header_size_pos = 0
tad_header_size_size = 4
tad_import_type_size = 2
tad_import_type_pos = 4
tad_version = 0
tad_version_pos = 6
tad_version_size = 2
tad_cert_size_pos = 8
tad_cert_size_size = 4
tad_ticket_size_pos = 0x10
tad_ticket_size_size = 4
tad_tmd_size_pos = 0x14
tad_tmd_size_size = 4
tad_enc_content_size_pos = 0x18
tad_enc_content_size_size = 4

wad_title_id_default_preamble = [0, 1, 0, 1]
tad_title_id_default_preamble = [0, 3, 0, 4]
tadwad_title_id_default_post = [0x54, 0x45, 0x53, 0x54] # TEST
tadwad_title_version_default = [0, 0] # TEST
wad_sys_version_default = [0, 0, 0, 1, 0, 0, 0, 0x38]
tad_sys_version_default = [0, 0, 0, 0, 0, 0, 0, 0]
tad_title_type_default = 0
wad_title_type_default = 1
tadwad_group_id_default = [0x30, 0x30]

base_import_string = "Is"

# Appends a section to the TAD.
# It makes sure the sections are aligned to 64 bytes.
def tadwad_add_section(tad, section):
	tad = pad_data_to_boundary_align(tad)

	tad += section

	tad = pad_data_to_boundary_align(tad)

	return tad

# Function which populates the actual TAD.
# Gets as input the sections, of which the sizes are put into the header.
# The sections themselves are then appended after the header, in order.
def tadwad_create_base(tad_import_string, cert_chain, ticket, tmd, enc_content):

	enc_contents_blob = []
	for i in range(len(enc_content)):
		enc_contents_blob += enc_content[i]
		# This seems needed for contents in WADs
		enc_contents_blob = pad_data_to_boundary_align(enc_contents_blob)

	tad = [0] * tad_header_size

	write_int_to_list_of_bytes(tad, tad_header_size_pos, tad_header_size, tad_header_size_size)

	tad_import_type = bytes(tad_import_string, 'ascii')[:tad_import_type_size]
	write_bytes_to_list_of_bytes(tad, tad_import_type_pos, tad_import_type)

	write_int_to_list_of_bytes(tad, tad_version_pos, tad_version, tad_version_size)

	write_int_to_list_of_bytes(tad, tad_cert_size_pos, len(cert_chain), tad_cert_size_size)

	write_int_to_list_of_bytes(tad, tad_ticket_size_pos, len(ticket), tad_ticket_size_size)

	write_int_to_list_of_bytes(tad, tad_tmd_size_pos, len(tmd), tad_tmd_size_size)

	write_int_to_list_of_bytes(tad, tad_enc_content_size_pos, len(enc_contents_blob), tad_enc_content_size_size)

	tad = tadwad_add_section(tad, cert_chain)
	tad = tadwad_add_section(tad, ticket)
	tad = tadwad_add_section(tad, tmd)
	tad = tadwad_add_section(tad, enc_contents_blob)

	return tad

# Function which from a NDS ROM produces a TAD.
# Supports multiple contents.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# These and cert_chain are then combined by tadwad_create_base
# to create the actual TAD.
def tad_create_rom(data_list, nds_rom_index, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, tad_import_string = base_import_string):
	data_list = pad_data_list_for_tmd(data_list)

	nds_rom = data_list[nds_rom_index]
	cert_signer_data_list = read_certchain(cert_chain)
	fill_signer_data_name_with_list(cert_signer_data_list, ticket_signer_data, "TIK", "Could not find ticket key in cert!")
	fill_signer_data_name_with_list(cert_signer_data_list, tmd_signer_data, "TMD", "Could not find TMD key in cert!")
	title_key, ticket = ticket_create_rom(nds_rom, ecdh_data, common_key, ticket_signer_data)
	tmd = tmd_create_rom(data_list, nds_rom_index, tmd_signer_data)
	enc_content = []
	for i in range(len(data_list)):
		enc_content += [data_to_enc_content_init_iv(data_list[i], i, title_key)]

	if not is_signature_valid(ticket, ticket_signer_data):
		print("Ticket signing error!")
		return []

	if not is_signature_valid(tmd, tmd_signer_data):
		print("TMD signing error!")
		return []

	return tadwad_create_base(tad_import_string, cert_chain, ticket, tmd, enc_content)

# Function which from a NDS ROM produces a TAD.
# Supports only one content.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# Calls the more generic tad_create_rom.
def tad_create_solo_nds_rom(nds_rom, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, tad_import_string = base_import_string):
	return tad_create_rom([nds_rom], 0, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, tad_import_string = tad_import_string)

# Function which from Wii files produces a WAD.
# Supports multiple contents.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# These and cert_chain are then combined by tadwad_create_base
# to create the actual TAD.
def wad_create_wii_files(data_list, boot_content_index, title_id, title_version, sys_version, title_type, group_id, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, wad_import_string = base_import_string):
	data_list = pad_data_list_for_tmd(data_list)

	if title_id is None:
		title_id = bytes(wad_title_id_default_preamble + tadwad_title_id_default_post) # TEST
	if title_version is None:
		title_version = bytes(tadwad_title_version_default)
	if sys_version is None:
		sys_version = bytes(wad_sys_version_default)
	if title_type is None:
		title_type = wad_title_type_default
	if group_id is None:
		group_id = bytes(tadwad_group_id_default)

	cert_signer_data_list = read_certchain(cert_chain)
	fill_signer_data_name_with_list(cert_signer_data_list, ticket_signer_data, "TIK", "Could not find ticket key in cert!")
	fill_signer_data_name_with_list(cert_signer_data_list, tmd_signer_data, "TMD", "Could not find TMD key in cert!")
	title_key, ticket = ticket_create_all(ecdh_data, common_key, title_id, title_version, ticket_signer_data, False)
	tmd = tmd_create_all(data_list, boot_content_index, title_id, title_version, title_type, group_id, None, None, None, sys_version, tmd_signer_data, False, None)
	enc_content = []
	for i in range(len(data_list)):
		enc_content += [data_to_enc_content_init_iv(data_list[i], i, title_key)]

	if not is_signature_valid(ticket, ticket_signer_data):
		print("Ticket signing error!")
		return []

	if not is_signature_valid(tmd, tmd_signer_data):
		print("TMD signing error!")
		return []

	return tadwad_create_base(wad_import_string, cert_chain, ticket, tmd, enc_content)

# Function which from Wii banner, a Wii main content
# and a Wii NAND Boot Program produces a WAD.
# Supports only three contents.
# Requires input parameters for Title information.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# Calls the more generic tad_create_rom.
def wad_create_solo_wii_main_content(wii_main_content, wii_nand_boot_program, banner_data, title_id, title_version, sys_version, title_type, group_id, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, wad_import_string = base_import_string):
	if banner_data is None:
		banner_data = pad_data_to_boundary_align(bytes([0]))
	return wad_create_wii_files([banner_data, wii_main_content, wii_nand_boot_program], 2, title_id, title_version, sys_version, title_type, group_id, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, wad_import_string = wad_import_string)

# Base function which from a DataTADWAD produces a TAD or a WAD.
# Supports multiple contents.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# These and cert_chain are then combined by tadwad_create_base
# to create the actual TAD.
# Requires extra TAD-specific parameters (None for WADs).
# Should be called after the NDS ROM (for TADs) has been parsed
# to fill in_DataTADWAD.
def tadwad_create_specs_base(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, public_sav_size, private_sav_size, parental_control, is_tad):
	in_DataTADWAD.sanitize()

	data_list = []
	for i in range(len(in_DataTADWAD.cmds)):
		data_list += [in_DataTADWAD.cmds[i].decrypted_content]
	data_list = pad_data_list_for_tmd(data_list)

	cert_signer_data_list = read_certchain(cert_chain)
	fill_signer_data_name_with_list(cert_signer_data_list, ticket_signer_data, "TIK", "Could not find ticket key in cert!")
	fill_signer_data_name_with_list(cert_signer_data_list, tmd_signer_data, "TMD", "Could not find TMD key in cert!")

	title_key, ticket = ticket_create_all(ecdh_data, common_key, in_DataTADWAD.title_id, in_DataTADWAD.title_version, ticket_signer_data, is_tad)
	tmd = tmd_create_all(data_list, in_DataTADWAD.boot_index, in_DataTADWAD.title_id, in_DataTADWAD.title_version, in_DataTADWAD.title_type, in_DataTADWAD.group_id, public_sav_size, private_sav_size, parental_control, in_DataTADWAD.sys_version, tmd_signer_data, is_tad, in_DataTADWAD.cmds)
	enc_content = []
	for i in range(len(data_list)):
		enc_content += [data_to_enc_content_init_iv(data_list[i], i, title_key)]

	if not is_signature_valid(ticket, ticket_signer_data):
		print("Ticket signing error!")
		return []

	if not is_signature_valid(tmd, tmd_signer_data):
		print("TMD signing error!")
		return []

	return tadwad_create_base(in_DataTADWAD.curr_import_string, cert_chain, ticket, tmd, enc_content)

# Function which from a DataTADWAD produces a TAD.
# Supports multiple contents.
# Checks the NDS ROM header first.
def tad_create_specs(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data):
	public_sav_size = 0
	private_sav_size = 0
	parental_control = None

	if not in_DataTADWAD.is_data_title:
		nds_rom = in_DataTADWAD.cmds[in_DataTADWAD.boot_index].decrypted_content
		nds_rom_header_data = NDSRomHeaderTADInfo(nds_rom)
		if in_DataTADWAD.title_id is None:
			in_DataTADWAD.title_id = nds_rom_header_data.title_id
		if in_DataTADWAD.title_version is None:
			in_DataTADWAD.title_version = nds_rom_header_data.title_version
		if in_DataTADWAD.group_id is None:
			in_DataTADWAD.group_id = nds_rom_header_data.group_id
		public_sav_size = nds_rom_header_data.public_sav_size
		private_sav_size = nds_rom_header_data.private_sav_size
		parental_control = nds_rom_header_data.parental_control
		if in_DataTADWAD.title_id != nds_rom_header_data.title_id:
			print("Title ID in specs file and NDS ROM header do not match!")
			print("Defaulting to the one specified in the specs file...")
		if in_DataTADWAD.title_version != nds_rom_header_data.title_version:
			print("Title Version in specs file and NDS ROM header do not match!")
			print("Defaulting to the one specified in the specs file...")
		if in_DataTADWAD.group_id != nds_rom_header_data.group_id:
			print("Group ID in specs file and NDS ROM header do not match!")
			print("Defaulting to the one specified in the specs file...")

	return tadwad_create_specs_base(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, public_sav_size, private_sav_size, parental_control, True)

# Function which from a DataTADWAD produces a WAD.
# Supports multiple contents.
def wad_create_specs(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data):
	return tadwad_create_specs_base(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, None, None, None, False)

# Function which from a DataTADWAD produces a TAD or a WAD.
# Supports multiple contents.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
def tadwad_create_specs(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data):
	if in_DataTADWAD.is_tad:
		return tad_create_specs(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data)
	return wad_create_specs(in_DataTADWAD, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data)

# Extracts the sections from a TAD/WAD file.
# Does no processing.
# Returns import string, cert, ticket, TMD and encrypted content blob.
def tadwad_get_pieces(tad_data):
	curr_header_size = read_int_from_list_of_bytes(tad_data, tad_header_size_pos, tad_header_size_size)
	curr_import_string = read_string_from_list_of_bytes(tad_data, tad_import_type_pos, tad_import_type_size)
	curr_tad_version = read_int_from_list_of_bytes(tad_data, tad_version_pos, tad_version_size)
	curr_cert_chain_size = read_int_from_list_of_bytes(tad_data, tad_cert_size_pos, tad_cert_size_size)
	curr_ticket_size = read_int_from_list_of_bytes(tad_data, tad_ticket_size_pos, tad_ticket_size_size)
	curr_tmd_size = read_int_from_list_of_bytes(tad_data, tad_tmd_size_pos, tad_tmd_size_size)
	curr_enc_content_size = read_int_from_list_of_bytes(tad_data, tad_enc_content_size_pos, tad_enc_content_size_size)

	next_pos = pad_pos_to_boundary_align(curr_header_size)
	cert_chain = tad_data[next_pos:next_pos + curr_cert_chain_size]
	next_pos += pad_pos_to_boundary_align(curr_cert_chain_size)
	ticket = tad_data[next_pos:next_pos + curr_ticket_size]
	next_pos += pad_pos_to_boundary_align(curr_ticket_size)
	tmd = tad_data[next_pos:next_pos + curr_tmd_size]
	next_pos += pad_pos_to_boundary_align(curr_tmd_size)
	enc_content = tad_data[next_pos:next_pos + curr_enc_content_size]
	next_pos += pad_pos_to_boundary_align(curr_enc_content_size)

	return curr_import_string, cert_chain, ticket, tmd, enc_content

class DataTADWAD:
	import_str_specs_str = "IMPORT STRING"
	title_id_specs_str = "TITLE ID"
	title_version_specs_str = "TITLE VERSION"
	sys_version_specs_str = "SYS VERSION"
	title_type_specs_str = "TITLE TYPE"
	group_id_specs_str = "GROUP ID"
	num_cmds_specs_str = "NUM_CMDS"
	base_cmd_specs_str = "CMD"
	is_tad_specs_str = "IS TAD"
	DataTADWAD_specs_str = "TADWAD SPECS"
	DataTADWAD_version = 2

	def __init__(self, curr_import_string=None, title_id=None, title_version=None, sys_version=None, title_type=None, group_id=None, is_tad=None, cmds=[]):
		self.curr_import_string=curr_import_string
		self.title_id=title_id
		self.title_version=title_version
		self.sys_version=sys_version
		self.title_type=title_type
		self.group_id=group_id
		if is_tad is None:
			is_tad = True
		self.is_tad=is_tad
		self.cmds=cmds
		self.is_data_title = False
		if self.is_tad and (self.title_id is not None) and are_bytes_same(self.title_id[:len(dsi_title_is_data)], dsi_title_is_data):
			self.is_data_title = True
		# I think this is a data title?! Maybe not though?!
		if (not self.is_tad) and (self.title_id is not None) and  are_bytes_same(self.title_id[:len(wii_title_is_data)], wii_title_is_data):
			self.is_data_title = True

	def sanitize_cmds(self):
		self.boot_index = None
		boot_index_list = []
		sanitized_cmds = []
		for i in range(len(self.cmds)):
			if self.cmds[i].can_be_used_to_build():
				sanitized_cmds += [self.cmds[i]]
		self.cmds = sanitized_cmds
		for i in range(len(self.cmds)):
			if self.cmds[i].is_boot_content:
				boot_index_list += [i]
		if len(boot_index_list) >= 1:
			self.boot_index = boot_index_list[0]
			if len(boot_index_list) > 1:
				print("Multiple boot indexes found. Using first! " + str(boot_index_list))

		if len(boot_index_list) == 0:
			target_boot_index = None
			if self.is_data_title and self.is_tad:
				target_boot_index = 0
			if self.is_data_title and (not self.is_tad):
				target_boot_index = len(self.cmds) - 1
			if target_boot_index is not None:
				print("No boot content found... Title ID does not match data only!")
				print("Defaulting to " + str(target_boot_index) + "!")
			else:
				# Default. For non-bootable titles.
				target_boot_index = 0
			# Can a shared content be bootable?
			self.boot_index = target_boot_index

	def sanitize(self):
		if self.is_tad is None:
			self.is_tad = True
		if self.curr_import_string is None:
			self.curr_import_string = base_import_string
		if self.title_id is None:
			title_id_preamble = tad_title_id_default_preamble
			if not self.is_tad:
				title_id_preamble = wad_title_id_default_preamble
			self.title_id = bytes(title_id_preamble + tadwad_title_id_default_post) # TEST
		if self.title_version is None:
			self.title_version = bytes(tadwad_title_version_default)
		if self.sys_version is None:
			self.sys_version = bytes(tad_sys_version_default)
			if not self.is_tad:
				self.sys_version = bytes(wad_sys_version_default)
		if self.title_type is None:
			self.title_type = tad_title_type_default
			if not self.is_tad:
				self.title_type = wad_title_type_default
		if self.group_id is None:
			self.group_id = bytes(tadwad_group_id_default)

	def get_title_id_name(self):
		return bytes_list_to_hex_str(self.title_id, spacer = "") + "_" + bytes_list_to_hex_str(self.title_version, spacer = "")

	def get_is_tad_string(self):
		if self.is_tad:
			return "1"
		return "0"

	def specs_str(self, file_preamble = ""):
		out_str = ""
		out_str += DataTADWAD.DataTADWAD_specs_str + ": " + str(DataTADWAD.DataTADWAD_version) + "\n"
		out_str += DataTADWAD.import_str_specs_str + ": " + self.curr_import_string + "\n"
		out_str += DataTADWAD.title_id_specs_str + ": " + bytes_list_to_hex_str(self.title_id) + "\n"
		out_str += DataTADWAD.title_version_specs_str + ": " + bytes_list_to_hex_str(self.title_version) + "\n"
		out_str += DataTADWAD.sys_version_specs_str + ": " + bytes_list_to_hex_str(self.sys_version) + "\n"
		out_str += DataTADWAD.title_type_specs_str + ": " + str(self.title_type) + "\n"
		out_str += DataTADWAD.group_id_specs_str + ": " + bytes_list_to_hex_str(self.group_id) + "\n"
		out_str += DataTADWAD.is_tad_specs_str + ": " + self.get_is_tad_string() + "\n"
		out_str += DataTADWAD.num_cmds_specs_str + ": " + str(len(self.cmds)) + "\n"

		for i in range(len(self.cmds)):
			out_str += self.cmds[i].specs_str(DataTADWAD.base_cmd_specs_str + " " + str(i), file_preamble=file_preamble)

		return out_str

	# Takes in input a specs list of lines, already splitted...
	def read_specs(specs):
		specs_DataTADWAD_version = read_int_of_string_start_in_list(specs, DataTADWAD.DataTADWAD_specs_str)
		if specs_DataTADWAD_version is None:
			print("Could not find specs version!")
			return None
		if specs_DataTADWAD_version != DataTADWAD.DataTADWAD_version:
			print("Specs version does not match!")
			return None

		curr_import_string = read_string_of_string_start_in_list(specs, DataTADWAD.import_str_specs_str)

		title_id = read_bytes_of_string_start_in_list(specs, DataTADWAD.title_id_specs_str, dsi_title_id_size)
		title_version = read_bytes_of_string_start_in_list(specs, DataTADWAD.title_version_specs_str, dsi_version_size)
		sys_version = read_bytes_of_string_start_in_list(specs, DataTADWAD.sys_version_specs_str, sys_version_size)
		title_type = read_int_of_string_start_in_list(specs, DataTADWAD.title_type_specs_str)
		group_id = read_bytes_of_string_start_in_list(specs, DataTADWAD.group_id_specs_str, nds_groud_id_size)
		num_cmds = read_int_of_string_start_in_list(specs, DataTADWAD.num_cmds_specs_str)
		is_tad = read_bool_of_string_start_in_list(specs, DataTADWAD.is_tad_specs_str)

		if num_cmds > 0x1FF:
			num_cmds = 0x1FF

		cmds = []
		for i in range(num_cmds):
			cmds += [DataCMD.read_specs(specs, i, DataTADWAD.base_cmd_specs_str + " " + str(i))]

		return DataTADWAD(curr_import_string=curr_import_string, title_id=title_id, title_version=title_version, sys_version=sys_version, title_type=title_type, group_id=group_id, is_tad=is_tad, cmds=cmds)

# Extracts the decrypted files and the relevant data from a TAD.
# Returns the import string, the title_id, the title_version, the title_type,
# the group_id and the tmd_cmds (DataCMD objects).
# As a DataTADWAD object.
def tadwad_extract(tad_data, common_key, is_tad):
	curr_import_string, cert_chain, ticket, tmd, enc_content_blob = tadwad_get_pieces(tad_data)
	cert_signer_data_list = read_certchain(cert_chain)
	ticket_data_read = read_ticket(ticket, common_key)
	tmd_data_read = read_tmd(tmd)

	if not are_bytes_same(ticket_data_read.title_id, tmd_data_read.title_id):
		print("Ticket and TMD title ID do not match!")
	title_id = tmd_data_read.title_id

	if not are_bytes_same(ticket_data_read.title_version, tmd_data_read.title_version):
		print("Ticket and TMD title version do not match!")
	title_version = tmd_data_read.title_version

	ticket_signer_data = find_signer_in_list_by_name(cert_signer_data_list, ticket_data_read.signer_name)
	tmd_signer_data = find_signer_in_list_by_name(cert_signer_data_list, tmd_data_read.signer_name)

	if not is_signature_valid(ticket, ticket_signer_data):
		print("Ticket signature invalid!")

	if not is_signature_valid(tmd, tmd_signer_data):
		print("TMD signature invalid!")

	content_pos = 0
	for single_tmd_cmd in tmd_data_read.cmds:
		enc_content = enc_content_blob[content_pos:content_pos + single_tmd_cmd.content_size]
		dec_content = enc_content_to_data_init_iv(enc_content, single_tmd_cmd.content_index, ticket_data_read.dec_title_key)
		content_pos += pad_pos_to_boundary_align(single_tmd_cmd.content_size)
		single_tmd_cmd.decrypted_content = dec_content

	return DataTADWAD(curr_import_string=curr_import_string, title_id=title_id, title_version=title_version, sys_version=tmd_data_read.sys_version, title_type=tmd_data_read.title_type, group_id=tmd_data_read.group_id, is_tad=is_tad, cmds=tmd_data_read.cmds)
