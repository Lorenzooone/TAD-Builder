from .enc_dec import nds_rom_to_enc_content_init_iv, is_signature_valid
from .ticket import ticket_create_rom
from .tmd import tmd_create_rom
from .nds_rom_header import boundary_align
from .utils import *
from .cert import read_certchain
from .signer import fill_signer_data_name_with_list

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

# Appends a section to the TAD.
# It makes sure the sections are aligned to 64 bytes.
def tad_add_section(tad, section):
	if (len(tad) % boundary_align) != 0:
		tad += [0] * (boundary_align - (len(tad) % boundary_align))

	tad += section

	if (len(tad) % boundary_align) != 0:
		tad += [0] * (boundary_align - (len(tad) % boundary_align))

	return tad

# Function which populates the actual TAD.
# Gets as input the sections, of which the sizes are put into the header.
# The sections themselves are then appended after the header, in order.
def tad_create_base(tad_import_string, cert_chain, ticket, tmd, enc_content):

	tad = [0] * tad_header_size

	write_int_to_list_of_bytes(tad, tad_header_size_pos, tad_header_size, tad_header_size_size)

	tad_import_type = bytes(tad_import_string, 'ascii')[:tad_import_type_size]
	write_bytes_to_list_of_bytes(tad, tad_import_type_pos, tad_import_type)

	write_int_to_list_of_bytes(tad, tad_version_pos, tad_version, tad_version_size)

	write_int_to_list_of_bytes(tad, tad_cert_size_pos, len(cert_chain), tad_cert_size_size)

	write_int_to_list_of_bytes(tad, tad_ticket_size_pos, len(ticket), tad_ticket_size_size)

	write_int_to_list_of_bytes(tad, tad_tmd_size_pos, len(tmd), tad_tmd_size_size)

	write_int_to_list_of_bytes(tad, tad_enc_content_size_pos, len(enc_content), tad_enc_content_size_size)

	tad = tad_add_section(tad, cert_chain)
	tad = tad_add_section(tad, ticket)
	tad = tad_add_section(tad, tmd)
	tad = tad_add_section(tad, enc_content)

	return tad

# Function which from a NDS ROM produces a TAD.
# The input parameters are used to create the ticket,
# the TMD (Title MetaData) and the encrypted content.
# These and cert_chain are then combined by tad_create_base
# to create the actual TAD.
def tad_create_rom(nds_rom, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data, tad_import_string = "Is"):
	cert_signer_data_list = read_certchain(cert_chain)
	fill_signer_data_name_with_list(cert_signer_data_list, ticket_signer_data, "TIK", "Could not find ticket key in cert!")
	fill_signer_data_name_with_list(cert_signer_data_list, tmd_signer_data, "TMD", "Could not find TMD key in cert!")
	title_key, ticket = ticket_create_rom(nds_rom, ecdh_data, common_key, ticket_signer_data)
	tmd = tmd_create_rom(nds_rom, tmd_signer_data)
	enc_content = nds_rom_to_enc_content_init_iv(nds_rom, title_key)

	if not is_signature_valid(ticket, ticket_signer_data):
		print("Ticket signing error!")
		return []

	if not is_signature_valid(tmd, tmd_signer_data):
		print("TMD signing error!")
		return []

	return tad_create_base(tad_import_string, cert_chain, ticket, tmd, enc_content)
