import sys
from python_files.enc_dec import *
from python_files.key_file_reader_writer import read_key_file, write_key_file
from python_files.ticket import ticket_create_rom
from python_files.tmd import tmd_create_rom, tmd_create_solo_nds_rom
from python_files.cert import cert_create
from python_files.tad import tad_create_rom, tad_create_solo_nds_rom, tadwad_extract, DataTADWAD, tadwad_create_specs, wad_create_solo_wii_main_content
from python_files.signer import Signer
from python_files.file_io import *
from python_files.menu_commands import *
from python_files.menu import MenuEntry

def signer_assigner(name, key_filename):
	kind, pub_exp, modulus, priv_exp = read_key_file(key_filename)

	if (pub_exp is None) or (modulus is None) or (priv_exp is None):
		return Signer(name=name, modulus=modulus, pub_exp=pub_exp, priv_exp=priv_exp, kind=kind)

	if kind == "":
		# This is an approximation... :/
		rsa2048_signing_size = getKeyForSigningKind("rsa2048").key_size
		ecdh_signing_size = getKeyForSigningKind("ecdh").key_size
		if (len(pub_exp) > rsa2048_signing_size) or (len(modulus) > rsa2048_signing_size) or (len(priv_exp) > rsa2048_signing_size):
			kind = "rsa4096"
		elif (len(pub_exp) > ecdh_signing_size) or (len(modulus) > ecdh_signing_size) or (len(priv_exp) > ecdh_signing_size):
			kind = "rsa2048"
		else:
			kind = "ecdh"

	return Signer(name=name, modulus=modulus, pub_exp=pub_exp, priv_exp=priv_exp, kind=kind)

def signer_writer(signer_data, key_filename):
	write_key_file(key_filename, signer_data.pub_exp, signer_data.modulus, signer_data.priv_exp, key_kind=signer_data.kind)

# Ensures that a file is properly signed by a certificate.
def main_check_signature(filtered_argv, menu_option):

	data = read_file_bytes(filtered_argv[0], accept_dash=False)
	if data is None:
		return
	cert = read_file_bytes(filtered_argv[1], accept_dash=False)
	if cert is None:
		return

	if is_signature_valid_cert(data, cert):
		print("Match!")
	else:
		print("Mismatch!")

# Signs a file. Then checks that the signature was done properly.
def main_sign(filtered_argv, menu_option):

	data_path = filtered_argv[0]
	data = read_file_bytes(data_path, accept_dash=False)
	if data is None:
		return

	signer_data = signer_assigner("", filtered_argv[1])

	out = bytes(sign_data(data, signer_data))

	if not is_signature_valid(out, signer_data):
		print("Signing error!")
		return

	out_path = "signed_" + data_path
	if len(filtered_argv) > 2:
		out_path = filtered_argv[2]

	write_file_bytes(out_path, out)

# Encrypts a NDS ROM. Takes in input the encrypted title_key, and requires
# the common_key to decrypt it before being able to use it.
def main_encrypt_nds_rom(filtered_argv, menu_option):

	nds_rom_path = filtered_argv[0]
	nds_rom = read_file_bytes(nds_rom_path, accept_dash=False)
	if nds_rom is None:
		return
	enc_title_key = read_file_bytes(filtered_argv[1], accept_dash=False)
	if enc_title_key is None:
		return
	common_key = read_file_bytes(filtered_argv[2])

	title_key = decrypt_title_key_nds_rom(nds_rom, enc_title_key, common_key)
	out = nds_rom_to_enc_content_init_iv(nds_rom, title_key)

	out_path = "enc_" + nds_rom_path
	if len(filtered_argv) > 3:
		out_path = filtered_argv[3]
	
	write_file_bytes(out_path, out)

# Creates a ticket from a NDS ROM. Takes in input
# the ecdh public key (easy to extract from existing TADs), the common_key,
# the ticket signer name and the ticket RSA key. (XS000...)
# Also checks that the signature was done properly.
def main_create_ticket(filtered_argv, menu_option):

	nds_rom = read_file_bytes(filtered_argv[0], accept_dash=False)
	if nds_rom is None:
		return
	ecdh_data = read_file_bytes(filtered_argv[1])
	common_key = read_file_bytes(filtered_argv[2])
	signer_data = signer_assigner(filtered_argv[3], filtered_argv[4])

	title_key, ticket = ticket_create_rom(nds_rom, ecdh_data, common_key, signer_data)

	if len(ticket) == 0:
		# Already errored out in ticket_create_rom...?!
		return

	ticket = bytes(ticket)

	if not is_signature_valid(ticket, signer_data):
		print("Signing error!")
		return

	out_path = "ticket.tik"
	if len(filtered_argv) > 5:
		out_path = filtered_argv[5]

	write_file_bytes(out_path, ticket)

# Creates the TMD (Title MetaData) from a NDS ROM. Takes in input
# the TMD signer name and the TMD RSA key. (CP000...)
# Also checks that the signature was done properly.
def main_create_tmd(filtered_argv, menu_option):

	nds_rom = read_file_bytes(filtered_argv[0], accept_dash=False)
	if nds_rom is None:
		return
	signer_data = signer_assigner(filtered_argv[1], filtered_argv[2])

	# tmd_create_rom supports multiple content
	tmd = tmd_create_solo_nds_rom(nds_rom, signer_data)

	if len(tmd) == 0:
		# Already errored out in tmd_create_solo_nds_rom...?!
		return

	tmd = bytes(tmd)

	if not is_signature_valid(tmd, signer_data):
		print("Signing error!")
		return

	out_path = "tmd.tmd"
	if len(filtered_argv) > 3:
		out_path = filtered_argv[3]

	write_file_bytes(out_path, tmd)

# Creates a new certificate. Takes in input the new name,
# the certificate signer name and the certificate RSA key. (CP000.../XS000...)
# Also checks that the signature was done properly.
# Self signing TMDs and tickets does not seem to work, for some reason...
def main_create_cert(filtered_argv, menu_option):
	name = filtered_argv[0]
	signer_data = signer_assigner(filtered_argv[1], filtered_argv[2])
	out_target = "rsa2048"

	out = cert_create(name, signer_data, target_key=out_target)

	if out is None:
		# Already errored out in cert create...?!
		return

	cert = bytes(out[0])
	out_signer_data = out[1]

	if not is_signature_valid(cert, signer_data):
		print("Signing error!")
		return

	out_path = str.lower(name)
	if len(filtered_argv) > 3:
		out_path = filtered_argv[3]

	write_file_bytes(out_path + ".cert", cert)
	signer_writer(out_signer_data, out_path + ".key")

# Creates a TAD from a NDS ROM.
# Requires the pre-baked cert_chain (easy to make/extract from existing TADs),
# as well as all the data needed to create a ticket (ecdh_data, common_key,
# the ticket signer name and the ticket RSA key) and all the data needed to
# create the TMD (the TMD signer name and the TMD RSA key).
# Also verifies the signature of the generated ticket and TMD.
def main_create_tad(filtered_argv, menu_option):

	nds_rom = read_file_bytes(filtered_argv[0], accept_dash=False)
	if nds_rom is None:
		return
	cert_chain = read_file_bytes(filtered_argv[1], ret_none=False)
	ecdh_data = read_file_bytes(filtered_argv[2])
	common_key = read_file_bytes(filtered_argv[3])

	ticket_signer_data = signer_assigner("", filtered_argv[4])

	tmd_signer_data = signer_assigner("", filtered_argv[5])

	# tad_create_rom supports multiple contents...
	tad = bytes(tad_create_solo_nds_rom(nds_rom, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data))

	out_path = "out.tad"
	if len(filtered_argv) > 6:
		out_path = filtered_argv[6]
	
	write_file_bytes(out_path, tad)

# Creates a TAD from a NDS ROM without doing any signature.
# Requires unlaunch to boot.
# Sets title_type to "Hb" to ease recognition.
def main_create_tad_no_sign(filtered_argv, menu_option):
	out_path = "out_nosign.tad"
	if len(filtered_argv) > 1:
		out_path = filtered_argv[1]
	main_create_tad([filtered_argv[0], "-", "-", "-", "-", "-", out_path], menu_option)

# Reads the content from a TAD/WAD. Extracts the files and then
# creates a .specs file to build it back.
def main_read_tad_wad(filtered_argv, menu_option, is_tad):
	tad_data = read_file_bytes(filtered_argv[0], accept_dash=False)
	if tad_data is None:
		return
	common_key = read_file_bytes(filtered_argv[1])
	out = tadwad_extract(tad_data, common_key, is_tad)

	base_out_path = ""
	if len(filtered_argv) > 2:
		base_out_path = filtered_argv[2]

	if(base_out_path == "-"):
		return

	write_file_lines(base_out_path + out.get_title_id_name() + ".specs", out.specs_str(file_preamble=base_out_path))
	for single_cmd in out.cmds:
		write_file_bytes(single_cmd.get_content_filename(file_preamble=base_out_path), single_cmd.decrypted_content)

# Reads the content from a TAD. Extracts the files and then
# creates a .specs file to build it back.
def main_read_tad(filtered_argv, menu_option):
	return main_read_tad_wad(filtered_argv, menu_option, True)

# Reads the content from a WAD. Extracts the files and then
# creates a .specs file to build it back.
def main_read_wad(filtered_argv, menu_option):
	return main_read_tad_wad(filtered_argv, menu_option, False)

# Creates a WAD from a set of Wii files.
# Optionally uses title-related data.
# Requires the pre-baked cert_chain (easy to make/extract from existing WADs),
# as well as all the data needed to create a ticket (ecdh_data, common_key,
# the ticket signer name and the ticket RSA key) and all the data needed to
# create the TMD (the TMD signer name and the TMD RSA key).
# Also verifies the signature of the generated ticket and TMD.
def main_create_wad(filtered_argv, menu_option):
	wii_main_content = read_file_bytes(filtered_argv[0], accept_dash=False)
	if wii_main_content is None:
		return
	wii_nand_boot_program = read_file_bytes(filtered_argv[1], accept_dash=False)
	if wii_nand_boot_program is None:
		return
	banner_data = read_file_bytes(filtered_argv[2])
	title_id = hex_str_to_bytes_list_no_spaces(filtered_argv[3], dsi_title_id_size)
	title_version = hex_str_to_bytes_list_no_spaces(filtered_argv[4], dsi_version_size)
	sys_version = hex_str_to_bytes_list_no_spaces(filtered_argv[5], sys_version_size)
	title_type = int_str_to_int(filtered_argv[6])
	group_id = hex_str_to_bytes_list_no_spaces(filtered_argv[7], nds_groud_id_size)

	cert_chain = read_file_bytes(filtered_argv[8], ret_none=False)
	ecdh_data = read_file_bytes(filtered_argv[9])
	common_key = read_file_bytes(filtered_argv[10])

	ticket_signer_data = signer_assigner("", filtered_argv[11])

	tmd_signer_data = signer_assigner("", filtered_argv[12])

	wad = bytes(wad_create_solo_wii_main_content(wii_main_content, wii_nand_boot_program, banner_data, title_id, title_version, sys_version, title_type, group_id, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data))

	out_path = "out.wad"
	if len(filtered_argv) > 13:
		out_path = filtered_argv[13]
	
	write_file_bytes(out_path, wad)

# Creates a WAD from a set of Wii files.
# Optionally uses title-related data.
# Requires modified firmware to boot.
def main_create_wad_no_sign(filtered_argv, menu_option):
	out_path = "out_nosign.wad"
	if len(filtered_argv) > 8:
		out_path = filtered_argv[8]
	main_create_wad(filtered_argv[:8] + ["-", "-", "-", "-", "-", out_path], menu_option)

# Creates a TAD or a WAD from a .specs file.
# Requires the pre-baked cert_chain (easy to make/extract from existing TADs
# or WADs), as well as all the data needed to create a ticket (ecdh_data,
# common_key, the ticket signer name and the ticket RSA key) and all the data
# needed to create the TMD (the TMD signer name and the TMD RSA key).
# Also verifies the signature of the generated ticket and TMD.
def main_build_from_specs(filtered_argv, menu_option, from_no_sign=False):
	specs_lines = read_file_lines(filtered_argv[0], accept_dash = False)
	if specs_lines is None:
		return

	cert_chain = read_file_bytes(filtered_argv[1], ret_none=False)
	ecdh_data = read_file_bytes(filtered_argv[2])
	common_key = read_file_bytes(filtered_argv[3])

	ticket_signer_data = signer_assigner("", filtered_argv[4])

	tmd_signer_data = signer_assigner("", filtered_argv[5])
	
	tadwad_data = DataTADWAD.read_specs(specs_lines)
	for single_cmd in tadwad_data.cmds:
		if single_cmd.has_valid_filename():
			single_cmd.decrypted_content = read_file_bytes(single_cmd.content_filename, accept_dash=False)

	tadwad_data.sanitize_cmds()
	if len(tadwad_data.cmds) == 0:
		print("WARNING: No valid content found... Is this wanted?")

	out = tadwad_create_specs(tadwad_data, cert_chain, ecdh_data, common_key, ticket_signer_data, tmd_signer_data)

	out_path = "out"
	if from_no_sign:
		out_path += "_no_sign"
	if tadwad_data.is_tad:
		out_path += ".tad"
	else:
		out_path += ".wad"

	if len(filtered_argv) > 6:
		out_path = filtered_argv[6]

	write_file_bytes(out_path, out)

# Creates a TAD or a WAD from a .specs file without doing any signature.
# Requires modded firmware to boot.
def main_build_from_specs_no_sign(filtered_argv, menu_option):
	new_filtered_argvs = [filtered_argv[0], "-", "-", "-", "-", "-"]
	if len(filtered_argv) > 1:
		new_filtered_argvs += [filtered_argv[1]]
	main_build_from_specs(new_filtered_argvs, menu_option, from_no_sign=True)

def print_menus_data(menus):
	print("-h/--help: an help page. For commands as well.")
	print("Available commands:\n")
	for i in range(len(menus)):
		print(menus[i].command + "\n\t" + menus[i].inner_help.to_desc_string())

def init_menus():
	menus = []
	menus += [MenuEntry(command_create_tad, main_create_tad)]
	menus += [MenuEntry(command_create_tad_nosign, main_create_tad_no_sign)]
	menus += [MenuEntry(command_create_wad, main_create_wad)]
	menus += [MenuEntry(command_create_wad_nosign, main_create_wad_no_sign)]
	menus += [MenuEntry(command_create_specs, main_build_from_specs)]
	menus += [MenuEntry(command_create_specs_nosign, main_build_from_specs_no_sign)]
	menus += [MenuEntry(command_check_sign, main_check_signature)]
	menus += [MenuEntry(command_sign, main_sign)]
	menus += [MenuEntry(command_enc_nds_rom, main_encrypt_nds_rom)]
	menus += [MenuEntry(command_create_ticket, main_create_ticket)]
	menus += [MenuEntry(command_create_tmd, main_create_tmd)]
	menus += [MenuEntry(command_create_cert, main_create_cert)]
	menus += [MenuEntry(command_read_tad, main_read_tad)]
	menus += [MenuEntry(command_read_wad, main_read_wad)]

	return menus

def init_menus_dict(menus):
	menus_dict = dict()
	for elem in menus:
		menus_dict[elem.command] = elem
	return menus_dict

def main(filtered_argv):
	menus = init_menus()
	menus_dict = init_menus_dict(menus)

	to_help = False
	to_option_help = False
	first_command = ""
	if len(filtered_argv) < 1:
		print("Missing command!")
		to_help = True
	else:
		first_command = filtered_argv[0].strip().lower()

	if (first_command == "-h") or (first_command == "--help"):
		to_help = True

	menu_option = menus_dict.get(first_command)
	if (not to_help) and (menu_option is None):
		print("Command " + first_command + " not available!")
		to_help = True

	if to_help:
		print_menus_data(menus)
		return

	next_filtered_argv = filtered_argv[1:]

	for elem in next_filtered_argv:
		option_param = elem.strip().lower()
		if (option_param == "-h") or (option_param == "--help"):
			to_option_help = True
			break

	if (not to_option_help) and (len(next_filtered_argv) < menu_option.inner_help.num_obbligatory):
		print("Not enough arguments!")
		to_option_help = True

	if to_option_help:
		print(menu_option.inner_help.to_string())
		return

	menu_option.function(next_filtered_argv, menu_option)

if __name__ == "__main__":
	main(sys.argv[1:])
