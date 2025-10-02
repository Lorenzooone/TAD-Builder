# TAD Builder
TAD Builder is a Python script to build a TAD, an installable DSiWare channel, as well as offering related functions.
TAD Builder in particular can be used to build homebrew TADs compatible with development consoles and NMenu with the tad\_build command.
tad\_build\_no\_sign can be used to build non-encrypted and non-signed homebrew TADs, which can be used with Unlaunch on retail consoles.

## Commands
TAD Builder has multiple available commands:
- tad\_build Builds the TAD file from a homebrew NDS ROM. Requires extra signature-related files.
- tad\_build\_no\_sign Builds a non-encrypted and non-signed TAD file from a homebrew NDS ROM.
- check\_file\_sign: Checks that a file is properly signed by the provided cert.
- sign\_file: Signs a file with the provided key.
- encrypt\_nds\_rom: Encrypts a NDS ROM with the encrypted title key and the common key.
- ticket\_build: Builds the ticket corresponding to a homebrew NDS ROM.
- tmd\_build Builds the TMD (Title MetaData) corresponding to a homebrew NDS ROM.
- cert\_build Builds a certificate which could be used to sign files.

Using -h or --help will show either a global help message, or a command-specific one.

## Dependencies
Dependencies can be installed by using `pip install -r requirements.txt`.

## Extra Files 
To build a TAD compatible with development consoles, certain key files are required.
- cfeirlte: certificate chain for the TAD. Used by Ticket and TMD. Raw bytes. Can be extracted by other development TADs.
- xs_dpki.eccPubKey: Public ECDH key for the Ticket. Optional. Raw bytes. Can be extracted by other development TADs.
- common_dpki.aesKey: Common AES key for the Ticket and content encryption. Raw bytes. Needs the development one (A1 60 4A 6A...). These keys can be dumped from the DSi bios7i.
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

If one has access to the TWL SDK, all of these files are intermediate output of the maketad.exe program which is normally used to create development TADs. If the program is arrested mid-execution (e.g. by pressing CTRL+C), the files are not deleted, and they can be used with TAD Builder.

Otherwise, when it comes to the RSA keys, if one has access to either the TWL SDK or the RVL SDK, xs\_dpki.rsa and cp\_dpki.rsa are included inside of maketad.exe and makewad.exe as clear text files.
In particular, one can find xs\_dpki.rsa and cp\_dpki.rsa by searching for the strings XS00000006 and CP00000007 respectively, and looking for the clear text file with the structure described above right after their certificate.

## Notes
- The tad\_build command does NOT pre-encrypt the secure area of the NDS ROM. To do that, you may need to use [ntool](https://github.com/smiRaphi/ntool) with the srl_retail2dev command. Then, TAD Builder may be used to create a working development TAD.
- It is possible to use this tool to repackage a retail homebrew TAD you dumped for a development console. Use [decrypt_tad](https://gist.github.com/rvtr/f1069530129b7a57967e3fc4b30866b4) to extract the NDS ROM, then use [ntool](https://github.com/smiRaphi/ntool) with the srl_retail2dev command. Finally, TAD Builder may be used to create a working development TAD.
- Commands can be quite long. Using scripts is advised.
- By default TAD Builder does not support WAD files (which are extremely similar to TAD files), but it could be expanded to do so.
- Self created certificates do not work for TADs (crash at startup), but they may work for WADs.
