from .enc_dec import data_to_enc_content_init_iv, is_signature_valid, pad_pos_to_enc, enc_content_to_data_init_iv
from .ticket import ticket_create_rom, read_ticket
from .tmd import tmd_create_rom, pad_data_list_for_tmd, read_tmd
from .nds_rom_header import boundary_align
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

base_import_string = "Is"

def get_next_section_start(curr_pos):
	curr_pos_modulus = curr_pos % boundary_align
	if curr_pos_modulus != 0:
		curr_pos += boundary_align - curr_pos_modulus
	return curr_pos

# Appends a section to the TAD.
# It makes sure the sections are aligned to 64 bytes.
def tad_add_section(tad, section):
	len_tad_modulus = len(tad) % boundary_align
	if len_tad_modulus != 0:
		tad += [0] * (boundary_align - len_tad_modulus)

	tad += section

	len_tad_modulus = len(tad) % boundary_align
	if len_tad_modulus != 0:
		tad += [0] * (boundary_align - len_tad_modulus)

	return tad

# Function which populates the actual TAD.
# Gets as input the sections, of which the sizes are put into the header.
# The sections themselves are then appended after the header, in order.
def tad_create_base(tad_import_string, cert_chain, ticket, tmd, enc_content):

	enc_contents_blob = []
	for i in range(len(enc_content)):
		enc_contents_blob += enc_content[i]

	tad = [0] * tad_header_size

	write_int_to_list_of_bytes(tad, tad_header_size_pos, tad_header_size, tad_header_size_size)

	tad_import_type = bytes(tad_import_string, 'ascii')[:tad_import_type_size]
	write_bytes_to_list_of_bytes(tad, tad_import_type_pos, tad_import_type)

	write_int_to_list_of_bytes(tad, tad_version_pos, tad_version, tad_version_size)

	write_int_to_list_of_bytes(tad, tad_cert_size_pos, len(cert_chain), tad_cert_size_size)

	write_int_to_list_of_bytes(tad, tad_ticket_size_pos, len(ticket), tad_ticket_size_size)

	write_int_to_list_of_bytes(tad, tad_tmd_size_pos, len(tmd), tad_tmd_size_size)

	write_int_to_list_of_bytes(tad, tad_enc_content_size_pos, len(enc_contents_blob), tad_enc_content_size_size)

	tad = tad_add_section(tad, cert_chain)
	tad = tad_add_section(tad, ticket)
	tad = tad_add_section(tad, tmd)
	tad = tad_add_section(tad, enc_contents_blob)

	return tad

# Function which from a NDS ROM produces a TAD.
# Supports multiple contents.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# These and cert_chain are then combined by tad_create_base
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

	return tad_create_base(tad_import_string, cert_chain, ticket, tmd, enc_content)

# Function which from a NDS ROM produces a TAD.
# Supports only one content.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# These and cert_chain are then combined by tad_create_base
# to create the actual TAD.
def tad_create_solo_nds_rom(nds_rom, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, tad_import_string = base_import_string):
	return tad_create_rom([nds_rom], 0, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, tad_import_string = tad_import_string)

# Extracts the sections from a TAD/WAD file.
# Does no processing.
# Returns import string, cert, ticket, TMD and encrypted content blob.
def tad_get_pieces(tad_data):
	curr_header_size = read_int_from_list_of_bytes(tad_data, tad_header_size_pos, tad_header_size_size)
	curr_import_string = read_string_from_list_of_bytes(tad_data, tad_import_type_pos, tad_import_type_size)
	curr_tad_version = read_int_from_list_of_bytes(tad_data, tad_version_pos, tad_version_size)
	curr_cert_chain_size = read_int_from_list_of_bytes(tad_data, tad_cert_size_pos, tad_cert_size_size)
	curr_ticket_size = read_int_from_list_of_bytes(tad_data, tad_ticket_size_pos, tad_ticket_size_size)
	curr_tmd_size = read_int_from_list_of_bytes(tad_data, tad_tmd_size_pos, tad_tmd_size_size)
	curr_enc_content_size = read_int_from_list_of_bytes(tad_data, tad_enc_content_size_pos, tad_enc_content_size_size)

	next_pos = get_next_section_start(curr_header_size)
	cert_chain = tad_data[next_pos:next_pos + curr_cert_chain_size]
	next_pos = get_next_section_start(next_pos + curr_cert_chain_size)
	ticket = tad_data[next_pos:next_pos + curr_ticket_size]
	next_pos = get_next_section_start(next_pos + curr_ticket_size)
	tmd = tad_data[next_pos:next_pos + curr_tmd_size]
	next_pos = get_next_section_start(next_pos + curr_tmd_size)
	enc_content = tad_data[next_pos:next_pos + curr_enc_content_size]
	next_pos = get_next_section_start(next_pos + curr_enc_content_size)

	return curr_import_string, cert_chain, ticket, tmd, enc_content

class DataTAD:
	import_str_specs_str = "IMPORT STRING"
	title_id_specs_str = "TITLE ID"
	title_version_specs_str = "TITLE VERSION"
	title_type_specs_str = "TITLE TYPE"
	group_id_specs_str = "GROUP ID"
	num_cmds_specs_str = "NUM_CMDS"
	base_cmd_specs_str = "CMD"
	datatad_version = 1

	def __init__(self, curr_import_string=base_import_string, title_id=None, title_version=None, title_type=None, group_id=None, cmds=[]):
		self.curr_import_string=curr_import_string
		self.title_id=title_id
		self.title_version=title_version
		self.title_type=title_type
		self.group_id=group_id
		self.cmds=cmds

	def get_title_id_name(self):
		return bytes_list_to_hex_str(self.title_id, spacer = "") + "_" + bytes_list_to_hex_str(self.title_version, spacer = "")

	def specs_str(self, file_preamble = ""):
		out_str = ""
		out_str += "TADWAD SPECS: " + str(DataTAD.datatad_version) + "\n"
		out_str += DataTAD.import_str_specs_str + ": " + self.curr_import_string + "\n"
		out_str += DataTAD.title_id_specs_str + ": " + bytes_list_to_hex_str(self.title_id) + "\n"
		out_str += DataTAD.title_version_specs_str + ": " + bytes_list_to_hex_str(self.title_version) + "\n"
		out_str += DataTAD.title_type_specs_str + ": " + str(self.title_type) + "\n"
		out_str += DataTAD.group_id_specs_str + ": " + bytes_list_to_hex_str(self.group_id) + "\n"
		out_str += DataTAD.num_cmds_specs_str + ": " + str(len(self.cmds)) + "\n"

		for i in range(len(self.cmds)):
			out_str += self.cmds[i].specs_str(DataTAD.base_cmd_specs_str + " " + str(i), file_preamble=file_preamble)

		return out_str

# Extracts the decrypted files and the relevant data from a TAD.
# Returns the import string, the title_id, the title_version, the title_type,
# the group_id and the tmd_cmds (DataCMD objects).
# As a DataTAD object.
def tad_extract(tad_data, common_key):
	curr_import_string, cert_chain, ticket, tmd, enc_content_blob = tad_get_pieces(tad_data)
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
		content_pos += pad_pos_to_enc(single_tmd_cmd.content_size)
		single_tmd_cmd.decrypted_content = dec_content

	return DataTAD(curr_import_string=curr_import_string, title_id=title_id, title_version=title_version, title_type=tmd_data_read.title_type, group_id=tmd_data_read.group_id, cmds=tmd_data_read.cmds)
