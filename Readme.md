# Paschwords
PowerShell module to manage your passwords. 

    • The Key files use AES-256-CBC encryption, with a PBKDF2-derived key from the master paschword. A random IV is generated for each key file and prepended to the encrypted content.
    • The paschword entries are encrypted using AES-256-CBC with a random IV. The ciphertext is also Base64-encoded for storage.
    • The database files are serialized to JSON, compressed with GZIP, then prepended with the AES IV, encrypted using AES-256-CBC, and finally Base64-encoded.

    Usage: pwmanage <database.pwdb> <keyfile.key> -noclip

# Overview
If no database/keyfile are specified, the defaults "paschwords.pwdb" and "paschwords.key" will be used.

When a password is retrieved, it will automatically be copied to the clipboard for 30 seconds, unless the -noclip option is used at launch time.

You can configure and number of options by modifying the entries in the "Paschwords.psd1" file located in the same directory as the module, or by using F9 to view and F10 to edit these configuration items.

Expiration dates only present the entries in a separate browse window for easy identification. No changes are made to the entries.

It is of course, best practice to save the key files somewhere distant from the databases. You could even save the database files on cloud storage, but I recommended saving the keys locally.

The initial configurations of the directories within the PSD1 file point to:

"DefaultPowerShellDirectory\Modules\Secure\keys" and "DefaultPowerShellDirectory\Modules\Paschwords\databases".

The term "DefaultPowerShellDirectory" is a placeholder that is evaluated within the module, redirecting these to your personal PowerShell directory. As stated above, I advise moving these somewhere else once you've setup the database and plan to use it long-term.

# Background
<table border=0><td valign=top width=50%>
I started this project when I realized that it was possible to create a JSON database with encrypted entries within PowerShell.
From there, it just made sense to create a full-fledged password manager.
The options required were obvious and the need for a master password was, as well.
I know this has very practical applications, because I work for clients who have systems that are extremely well locked down.
That means however, that they do not let you install unapproved software, but most will let you install PowerShell modules.
So, I created this module to be able to fill that niche and it just keeps growing.
The inital databases were plaintext, but those have been replaced with encrypted and compressed files, and several other advanced security features have been added along the way, including plans to add HMAC support.
<br><br>
In order to use this module the first time, you will either need to create databases and keys directories inside the module's directory,
or you will need to edit the PSD1 file to point these settings to a directory of your choosing.
You can then add or import entries as required.
</td>
<td valign=top width=50%><img src="https://raw.githubusercontent.com/Schvenn/Secure/refs/heads/main/screenshots/Main%20Menu.png"></td>
</table>

    # Core module details
    @{
    RootModule = 'Paschwords.psm1'
    ModuleVersion = '3.98'
    GUID = 'd4f71764-0e43-4632-8b35-0f0a79b36f62'
    Author = 'Schvenn'
    CompanyName = 'Plath Consulting Incorporated'
    Copyright = '(c) Craig Plath. All rights reserved.'
    Description = 'Secure password manager using AES encryption and key-based protection.'
    CompatiblePSEditions = @('Desktop')
    PowerShellVersion = '5.1'
    FunctionsToExport = @('paschwords')
    
    # Configuration data
    PrivateData = @{
    timetobootlimit = '60'
    defaultdatabase = 'paschwords.pwdb'
    dictionaryfile = 'common.dictionary'
    archiveslimit = '5'
    defaultkey = 'paschwords.key'
    expirywarning = '365'
    databasedir = 'DefaultPowerShellDirectory\Modules\Paschwords\databases'
    timeoutseconds = '900'
    delayseconds = '30'
    backupfrequency = '7'
    logretention = '30'
    keydir = 'DefaultPowerShellDirectory\Modules\Paschwords\keys'
    }}

A separate script "ValidateURLs.ps1" is included to test a file containing a list of URLs for connectivity. This is designed to be used with the Valid URLs search and export function within the module, but I am keeping it separate in order to ensure the Paschword manager remains completely offline and thereby limits its security exposure.
