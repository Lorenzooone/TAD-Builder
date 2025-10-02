from .enc_dec import sign_data, create_id, encrypt_title_key, decrypt_title_key
from .nds_rom_header import *
from .utils import *
from .key_sig import getKeySignatureKind

ticket_size_base = 0x164

signer_offset = 0
signer_size = 0x40
ecdh_data_offset = 0x40
ecdh_size = 0x3C
enc_title_key_offset = 0x7F
enc_title_key_size = 0x10
ticket_id_offset = 0x90
ticket_id_size = 0x08
console_id_offset = 0x98
console_id_size = 0x04
title_id_offset = 0x9C
title_version_offset = 0xA6
unknown_offset = 0xE1
unknown_value_observed = 0x84 # ???
ff_fill_offset = 0xE2
ff_fill_size = 0x20

# Creates the title key and the ticket.
# The title_id is used to create the title_key, which is then
# encrypted by the common_key.
# Uses the signer and the private key to sign the ticket.
# Even if the signature is not checked by the System Menu...
# The uncrypted title_key is returned as it is used to encrypt
# the content (e.g. the NDS ROM) in later functions.
# Returns an empty ticket in case of an error.
def ticket_create(ecdh_data, common_key, title_id, title_version, signer_data):
	title_key = create_id("title", title_id)[:enc_title_key_size]
	enc_title_key = encrypt_title_key(title_id, title_key, common_key)
	dec_title_key = decrypt_title_key(title_id, enc_title_key, common_key)
	if title_key != dec_title_key:
		print("Error with title key!")
		return title_key, []

	key_signature_kind = getKeySignatureKind(signer_data.kind)
	if key_signature_kind is None:
		print("Issue finding signature key")
		return title_key, []
	data_pos = key_signature_kind.tosign_pos
	ticket_size = data_pos + ticket_size_base

	ticket = [0] * ticket_size

	signer_name_bytes = signer_data.get_name_bytes(signer_size)

	write_bytes_to_list_of_bytes(ticket, data_pos + signer_offset, signer_name_bytes)

	if ecdh_data is not None:
		if len(ecdh_data) > ecdh_size:
			ecdh_data = ecdh_data[:ecdh_size]
		write_bytes_to_list_of_bytes(ticket, data_pos + ecdh_data_offset, ecdh_data)

	write_bytes_to_list_of_bytes(ticket, data_pos + enc_title_key_offset, enc_title_key)

	ticket_id = create_id("ticket", title_id)[:ticket_id_size]
	write_bytes_to_list_of_bytes(ticket, data_pos + ticket_id_offset, ticket_id)

	write_int_to_list_of_bytes(ticket, data_pos + console_id_offset, 0, console_id_size)

	write_bytes_to_list_of_bytes(ticket, data_pos + title_id_offset, title_id)

	write_bytes_to_list_of_bytes(ticket, data_pos + title_version_offset, title_version)

	ticket[data_pos + unknown_offset] = unknown_value_observed

	for i in range(ff_fill_size):
		ticket[data_pos + ff_fill_offset + i] = 0xFF

	ticket = sign_data(bytes(ticket), signer_data)
	return title_key, ticket

# Creates the title_key and the ticket for a NDS ROM.
# Extracts the title_id and title_version, which are used by ticket_create.
def ticket_create_rom(nds_rom, ecdh_data, common_key, signer_data):
	title_id = get_title_id_from_rom(nds_rom)
	title_version = nds_rom[nds_rom_location_version:nds_rom_location_version + dsi_version_size]
	return ticket_create(ecdh_data, common_key, title_id, title_version, signer_data)
