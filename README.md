# TADWAD Builder
TADWAD Builder is a Python script to: build TADs, installable DSiWare channels; build WADs, installable WiiWare channels; do other TAD/WAD related functions.

TADWAD Builder in particular has the specs\_build, tad\_build and wad\_build commands to build homebrew TADs or WADs compatible with development consoles (via TwlNmenu or Nmenu).

specs\_build\_no\_sign, tad\_build\_no\_sign and wad\_build\_no\_sign can be used to build non-encrypted and non-signed homebrew TADs or WADs, which can be used with modified firmware on retail consoles.

## Commands
TADWAD Builder has multiple available commands:
- tad\_build: Builds the TAD file from a homebrew NDS ROM. Requires extra signature-related files.
- tad\_build\_no\_sign: Builds a non-encrypted and non-signed TAD file from a homebrew NDS ROM.
- wad\_build: Builds the WAD file from a set of Wii files and title data. Requires extra signature-related files.
- wad\_build\_no\_sign: Builds a non-encrypted and non-signed WAD file from a set of Wii files and title data.
- specs\_build: Builds a TAD/WAD file from a .specs build file. Requires extra signature-related files.
- specs\_build\_no\_sign: Builds a non-encrypted and non-signed TAD/WAD file from a .specs build file.
- check\_file\_sign: Checks that a file is properly signed by the provided cert.
- sign\_file: Signs a file with the provided key.
- encrypt\_nds\_rom: Encrypts a NDS ROM with the encrypted title key and the common key.
- ticket\_build: Builds the ticket corresponding to a homebrew NDS ROM.
- tmd\_build: Builds the TMD (Title MetaData) corresponding to a homebrew NDS ROM.
- cert\_build: Builds a certificate which could be used to sign files.
- tad\_read: Extracts the data from a TAD file, and creates a .specs file to rebuild it with specs\_build. Requires the correct AES common key to decrypt the data.
- wad\_read: Extracts the data from a WAD file, and creates a .specs file to rebuild it with specs\_build. Requires the correct AES common key to decrypt the data.

Using -h or --help will show either a global help message, or a command-specific one.

## Dependencies
Dependencies can be installed by using `pip install -r requirements.txt`.

## Building with .specs files
Specs files can be used to store additional information to more easily build TADs and WADs.
They can especially be useful to create multi-content TADs and WADs, with user-chosen internal filenames.

It is recommended to use .specs files for complex build projects.

The specs\_build and specs\_build\_no\_sign commands take as input .specs files, examples for both a TAD and a WAD are included in the examples folder.

Alternatively, tad\_read and wad\_read commands also produce .specs files. These can be extracted from regularly built TADs and WADs (both regular ones and ones built with TADWAD Builder) and later adapted to fit the needs of the user.

## Building a TAD/WAD for Development Consoles
To build a TAD/WAD compatible with development consoles, certain key files are required.
- cfeirlte: certificate chain for the TAD. Used by Ticket and TMD. Raw bytes. Can be extracted from other development TADs/WADs.
- xs_dpki.eccPubKey: Public ECDH key for the Ticket. Optional. Raw bytes. Can be extracted from other development TADs/WADs.
- common_dpki.aesKey: Common AES key for the Ticket and content encryption. Raw bytes. Needs the development one (A1 60 4A 6A...). These keys can be dumped from the DSi bios7i. Also present in Wii BIOS.
- xs\_dpki.rsa: File containing the private (and public) RSA2048 key to sign development Tickets. Format described below.
- cp\_dpki.rsa: File containing the private (and public) RSA2048 key to sign development TMDs. Format described below.

In general, the RSA2048 key files use the following format:
```

<number of public exponent bytes> (i.e. 3)
<space separated clear text hexadecimal bytes for the public exponent> (i.e. 01 00 01)
<number of modulus bytes> (i.e. 256)
<space separated clear text hexadecimal bytes for the modulus>
<number of private exponent bytes> (i.e. 256)
<space separated clear text hexadecimal bytes for the private exponent>
...
```

If one has access to the TWL SDK, all of these files are intermediate output of the maketad.exe program which is normally used to create development TADs. If the program is arrested mid-execution (e.g. by pressing CTRL+C), the files are not deleted, and they can be used with TADWAD Builder.

Otherwise, when it comes to the RSA keys, if one has access to either the TWL SDK or the RVL SDK, xs\_dpki.rsa and cp\_dpki.rsa are included inside of maketad.exe and makeWad.exe as clear text files.
In particular, one can find xs\_dpki.rsa and cp\_dpki.rsa by searching for the strings XS00000006 and CP00000007 respectively, and looking for the clear text file with the structure described above right after their certificate.

## Notes
- The tad\_build command does NOT pre-encrypt the secure area of the NDS ROM. To do that, you may need to use [ntool](https://github.com/smiRaphi/ntool) with the srl_retail2dev command. Then, TADWAD Builder may be used to create a working development TAD.
- It is possible to use this tool to repackage a retail homebrew TAD you dumped for a development console. Use [decrypt_tad](https://gist.github.com/rvtr/f1069530129b7a57967e3fc4b30866b4) (or the tad\_read command, if you have the correct common key) to extract the NDS ROM, then use [ntool](https://github.com/smiRaphi/ntool) with the srl_retail2dev command. Finally, TADWAD Builder may be used to create a working development TAD.
- Commands can be quite long. Using scripts is advised.
- Self created certificates do not work for TADs (crash at startup, seems to be hardcoded to use the right certificates), but they may work for WADs. Untested, yet.
