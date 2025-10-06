from .menu_commands import *

desc_check_sign="Checks that a file is properly signed by the provided cert."
desc_sign="Signs a file with the provided key."
desc_enc_nds_rom="Encrypts a NDS ROM with the encrypted title key and the common key."
desc_create_ticket="Builds the ticket corresponding to a NDS ROM."
desc_create_tmd="Builds the TMD (Title MetaData) corresponding to a NDS ROM."
desc_create_cert="Builds a certificate which could be used to sign files."
desc_create_tad="Builds the TAD file from a NDS ROM."
desc_create_tad_nosign="Builds a non-encrypted TAD file from a NDS ROM."
desc_read_tad="Dumps the contents of a TAD file, and creates a specs file to re-create it."
desc_read_wad="Dumps the contents of a WAD file, and creates a specs file to re-create it."

omittable_with_dash_text = "Can be omitted with a '-'."
optional_text = "Optional parameter."

data_file_param = "data_file"
data_file_signature_param_desc = "signed file for which the signature should be checked."
data_file_signing_param_desc = "file which should be signed."
cert_file_param = "cert_file"
cert_file_signature_param_desc = "certificate containing the public key to verify the signature of a file."
key_file_param = "key_file"
key_file_param_desc = "file containing the private and public keys needed to sign and verify data."
ticket_key_file_param = "ticket_key_file"
ticket_key_file_param_desc = "file containing the private and public keys needed to sign and verify ticket data."
tmd_key_file_param = "tmd_key_file"
tmd_key_file_param_desc = "file containing the private and public keys needed to sign and verify TMD data."
key_name_param = "key_full_name"
key_name_param_desc = "full name of the signing key (e.g. Root-CA00000002-CP00000007)."
nds_rom_file_param = "nds_rom_file"
nds_rom_file_param_desc = "file containing a valid NDS ROM."
enc_title_key_param = "enc_title_key_file"
enc_title_key_param_desc = "file containing the encrypted title key."
common_key_param = "common_key_file"
common_key_param_desc = "file containing the common key."
ecdh_pubkey_param = "ecdh_pubkey_file"
ecdh_pubkey_param_desc = "file containing the public ecdh key."
out_path_param = "out_path"
out_path_param_desc = "output path."
out_path_no_extension_param = "out_path_no_extension"
out_path_no_extension_param_desc = "output path without any extension."
base_out_path_param = "base_out_path"
base_out_path_param_desc = "base output path used to determine final file output paths."
new_key_name_param = "new_key_partial_name"
new_key_name_param_desc = "partial name of the new signing key (e.g. HBTMDDSI)."
cert_chain_param = "cert_chain_file"
cert_chain_param_desc = "file containing the certificate chain."
tad_file_param = "tad_file"
tad_file_param_desc = "TAD file."
wad_file_param = "wad_file"
wad_file_param_desc = "WAD file."

class HelpText:
	def __init__(self, command, description):
		self.command = command
		self.description = description
		self.param_list = []
		self.help_list = []
		self.optionality_list = []
		self.dash_omittable_list = []
		self.num_obbligatory = 0

	def add_param(self, param_name, param_help, optionality = False, dash_omittable = False):
		self.param_list += [param_name]
		self.help_list += [param_help]
		if not optionality:
			self.num_obbligatory += 1
		self.optionality_list += [optionality]
		self.dash_omittable_list += [dash_omittable]

	def to_desc_string(self):
		return self.description

	def to_string(self):
		out_str = self.to_desc_string() + "\n\n"
		out_str += self.command
		if len(self.param_list) <= 0:
			return out_str

		for i in range(len(self.param_list)):
			param_str = self.param_list[i]
			if self.optionality_list[i]:
				param_str = "[" + param_str + "]"
			out_str += " " + param_str

		out_str += "\n"

		for i in range(len(self.help_list)):
			out_str += "\n\t" + self.param_list[i] + ": " + self.help_list[i]
			if self.optionality_list[i]:
				out_str += " " + optional_text
			if self.dash_omittable_list[i]:
				out_str += " " + omittable_with_dash_text

		out_str += "\n\t-h/--help: this help page."
		return out_str

inner_help_check_sign = HelpText(command_check_sign, desc_check_sign)
inner_help_check_sign.add_param(data_file_param, data_file_signature_param_desc)
inner_help_check_sign.add_param(cert_file_param, cert_file_signature_param_desc)

inner_help_sign = HelpText(command_sign, desc_sign)
inner_help_sign.add_param(data_file_param, data_file_signing_param_desc)
inner_help_sign.add_param(key_file_param, key_file_param_desc, dash_omittable=True)
inner_help_sign.add_param(out_path_param, out_path_param_desc, optionality=True)

inner_help_enc_nds_rom = HelpText(command_enc_nds_rom, desc_enc_nds_rom)
inner_help_enc_nds_rom.add_param(nds_rom_file_param, nds_rom_file_param_desc)
inner_help_enc_nds_rom.add_param(enc_title_key_param, enc_title_key_param_desc)
inner_help_enc_nds_rom.add_param(common_key_param, common_key_param_desc, dash_omittable=True)
inner_help_enc_nds_rom.add_param(out_path_param, out_path_param_desc, optionality=True)

inner_help_create_ticket = HelpText(command_create_ticket, desc_create_ticket)
inner_help_create_ticket.add_param(nds_rom_file_param, nds_rom_file_param_desc)
inner_help_create_ticket.add_param(ecdh_pubkey_param, ecdh_pubkey_param_desc, dash_omittable=True)
inner_help_create_ticket.add_param(common_key_param, common_key_param_desc, dash_omittable=True)
inner_help_create_ticket.add_param(key_name_param, key_name_param_desc, dash_omittable=True)
inner_help_create_ticket.add_param(key_file_param, key_file_param_desc, dash_omittable=True)
inner_help_create_ticket.add_param(out_path_param, out_path_param_desc, optionality=True)

inner_help_create_tmd = HelpText(command_create_tmd, desc_create_tmd)
inner_help_create_tmd.add_param(nds_rom_file_param, nds_rom_file_param_desc)
inner_help_create_tmd.add_param(key_name_param, key_name_param_desc, dash_omittable=True)
inner_help_create_tmd.add_param(key_file_param, key_file_param_desc, dash_omittable=True)
inner_help_create_tmd.add_param(out_path_param, out_path_param_desc, optionality=True)

inner_help_create_cert = HelpText(command_create_cert, desc_create_cert)
inner_help_create_cert.add_param(new_key_name_param, new_key_name_param_desc)
inner_help_create_cert.add_param(key_name_param, key_name_param_desc, dash_omittable=True)
inner_help_create_cert.add_param(key_file_param, key_file_param_desc, dash_omittable=True)
inner_help_create_cert.add_param(out_path_no_extension_param, out_path_no_extension_param_desc, optionality=True)

inner_help_create_tad = HelpText(command_create_tad, desc_create_tad)
inner_help_create_tad.add_param(nds_rom_file_param, nds_rom_file_param_desc)
inner_help_create_tad.add_param(cert_chain_param, cert_chain_param_desc, dash_omittable=True)
inner_help_create_tad.add_param(ecdh_pubkey_param, ecdh_pubkey_param_desc, dash_omittable=True)
inner_help_create_tad.add_param(common_key_param, common_key_param_desc, dash_omittable=True)
inner_help_create_tad.add_param(ticket_key_file_param, ticket_key_file_param_desc, dash_omittable=True)
inner_help_create_tad.add_param(tmd_key_file_param, tmd_key_file_param_desc, dash_omittable=True)
inner_help_create_tad.add_param(out_path_param, out_path_param_desc, optionality=True)

inner_help_create_tad_no_sign = HelpText(command_create_tad_nosign, desc_create_tad_nosign)
inner_help_create_tad_no_sign.add_param(nds_rom_file_param, nds_rom_file_param_desc)
inner_help_create_tad_no_sign.add_param(out_path_param, out_path_param_desc, optionality=True)

inner_help_read_tad = HelpText(command_read_tad, desc_read_tad)
inner_help_read_tad.add_param(tad_file_param, tad_file_param_desc)
inner_help_read_tad.add_param(common_key_param, common_key_param_desc, dash_omittable=True)
inner_help_read_tad.add_param(base_out_path_param, base_out_path_param_desc, optionality=True)

inner_help_read_wad = HelpText(command_read_wad, desc_read_wad)
inner_help_read_wad.add_param(wad_file_param, wad_file_param_desc)
inner_help_read_wad.add_param(common_key_param, common_key_param_desc, dash_omittable=True)
inner_help_read_wad.add_param(base_out_path_param, base_out_path_param_desc, optionality=True)

def add_inner_help_to_dict(help_dict, help_entry):
	help_dict[help_entry.command] = help_entry

inner_help_dict = dict()
add_inner_help_to_dict(inner_help_dict, inner_help_check_sign)
add_inner_help_to_dict(inner_help_dict, inner_help_sign)
add_inner_help_to_dict(inner_help_dict, inner_help_enc_nds_rom)
add_inner_help_to_dict(inner_help_dict, inner_help_create_ticket)
add_inner_help_to_dict(inner_help_dict, inner_help_create_tmd)
add_inner_help_to_dict(inner_help_dict, inner_help_create_cert)
add_inner_help_to_dict(inner_help_dict, inner_help_create_tad)
add_inner_help_to_dict(inner_help_dict, inner_help_create_tad_no_sign)
add_inner_help_to_dict(inner_help_dict, inner_help_read_tad)
add_inner_help_to_dict(inner_help_dict, inner_help_read_wad)
