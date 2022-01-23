# Lab_Timp

**Lab1** - This program prohibits creating, copying or renaming files with specified names in the current (the one it is in) directory (file masks can be used). The list of names or their templates must be stored in the file template.tbl, as text. This file must be protected from deletion, unauthorized viewing and modification. When installing the program, you can provide an option to disable it with a password stored in the first line of the template.tbl file in hashed form.
The program must be able to turn the protection mode on and off.

**Lab2** - This program asks for the user's name and enters this information into a text
file. If there is such a name in the file, it gives a message about it. After entering the information, the program must exit the program and inform the user of its usage limit (time or number of runs). When the limit of runs is reached, the program should
offer the user to purchase a full version or uninstall. When the program is reinstalled, it must report
its previous presence on this computer and check the previous usage limits (i.e. not allow them to be exceeded in total

**Lab3** 
1. Create a text document (sys.tat) that contains "System information"
2. Write a sysdoc.exe installer program for this document that pretends to install the update (showing the
update progress line) to some program (e.g. Notepad
or Paint):
- Requests the user for a folder (there should be an option
Requests the user for a folder (must use an existing folder and the option to create their own) to copy the "System Information",
- Writes to the folder a file with the executable code of the program
secur.exe (analogous to the requirements for template.tbl from lab 1), which protects sys.ta,
- Gathers (possible) information about the computer where the program is installed,
- Encodes this information and writes it into the sys.tat file,
- Signs it with the program user's private key
and writes the signature, for example, in the Windows registry under
𝐻𝐾𝐸𝑌𝐶𝑈𝑅𝑅𝐸𝑁𝑇𝑈𝑆𝐸𝑅 registry as the Signature value,
- Launches secur.exe to protect sys.tat against unauthorized access,
- Instructs secur.exe to run when the
Open function for sys.tat, so that the protection is triggered even after the
protection is triggered after OS restart (there are several ways of such "binding").
3. The secur.exe protection itself should include the following functionality:
- Requesting information from the user about the name of the registry section with the electronic digital signature (last name of the student),
- Reading the signature from the above registry section,
which is verified using the user's public key,
- Allow or deny viewing of the "System information" in the sys.tat file, depending on the correctness of the
key.
4) If the check fails, the protected program must stop operating and a corresponding message is displayed,
5) The information collected about the computer includes at least:
- User name,
- Computer name,
- Computer configuration (memory and CPU as a minimum) and OS version.
