# AES with bCrypt.h

Using bCrypt.h to do the AES encryption will expose the Windows API in the import address table (IAT), which may be blocked by some security solutions.
