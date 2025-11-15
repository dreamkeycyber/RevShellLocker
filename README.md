# RevShellLocker
#Reverse Shell which can AES encrypt local and onedrive directories/files.
#change the port and listening IP address to whatever you need.
# you will need to setup a listener on a VM or seperate machine running netcat or metasploit to receive the shell.

#The reverse shell works as any normal revershell in powershell would but adds functionality to encrypt onedrive files and directories with AES.

#This will not work on critical system files or directories which have specifically been placed in protected folders in defender.

#To encrypt a folder or file type command: 
encrypt file/folder password
#or
encrypt c:\path\to\folder\file password

#there is no file recovery if you forget your password and will have to retrieve previous version from one drive. 
#you can also recursively encrypt ALL backups by repeating the encrypt command if you so choose. Say there are only five file versions and you run encrypt 5 times you have encrypted every version of the file.

