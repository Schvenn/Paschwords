# Paschwords
A secure PowerShell module to manage and protect your passwords with industry-grade cryptography and integrity verification.

    • The master password is protected by PBKDF2 hashing, with separated authentication.
    • Per-entry and per-database a user registry integrated HMACs ensure integrity and detect tampering.
    • AES-256-CBC encryption with unique random IVs for each key file, each password entry, the user registry and the entire database.
    • The database and each password entry are also Base64 encoded.
    • The database storage is serialized to JSON, compressed with GZIP, then encrypted and Base64-encoded.
    • This means that each password is secured behind 7 layers of protection, even more if you include the user registry protection!
    • Designed for zero-trust handling; the keys, secrets and database are overwritten multiple times and removed using multiple methods between every significant action.
    • RBAC with two layers of authentication and 3 layers of privilege.
    • Brute-force protection against master password and individual user accounts.
    • External NTP time verifcation and hash verification for trusted source execution.
    • Timestamped activity logging which includes user details regarding standard and administrative activities.

    Usage: pwmanage <database.pwdb> <keyfile.key> -noclip

# Overview
If no database/keyfile are specified, the defaults "paschwords.pwdb" and "paschwords.key" will be used.

When a password is retrieved, it will automatically be copied to the clipboard for 30 seconds, unless the -noclip option is used at launch time.

You can configure and number of options by modifying the entries in the "Paschwords.psd1" file located in the same directory as the module, or by using F9 to view and F10 to edit these configuration items.

Expiration dates only present the entries in a separate browse entries screen for easy identification. No changes are made to the entries.

The initial configurations of the directories within the PSD1 file point to:

"DefaultPowerShellDirectory\Modules\Secure\keys" and "DefaultPowerShellDirectory\Modules\Paschwords\databases".

The term "DefaultPowerShellDirectory" is a placeholder that is evaluated within the module, redirecting these to a user's personal PowerShell directory, but these should be moved once setup is complete.

# Background
<table border=0><td valign=top width=50%>
I started this project when I realized that it was possible to create a JSON database with encrypted entries within PowerShell.
From there, it just made sense to create a full-fledged password manager.
The options required were obvious and the need for a master password was, as well.
I know this has very practical applications, because I work for clients who have systems that are extremely well locked down.
That means however, that they do not let you install unapproved software, but most will let you install PowerShell modules.
So, I created this module to be able to fill that niche and it just keeps growing.
<br><br>
The inital databases were plaintext, but those have been replaced with encrypted and compressed files, and several other advanced security features have been added along the way, including RBAC and HMAC integration.
<br><br>
A setup wizard and full help text is provided inline.
</td>
<td valign=top width=50%><img src="https://raw.githubusercontent.com/Schvenn/Secure/refs/heads/main/screenshots/Main%20Menu.png"></td>
</table>

    # Core module details
    @{
    RootModule = 'Paschwords.psm1'
    ModuleVersion = '4.25'
    GUID = 'd4f71764-0e43-4632-8b35-0f0a79b36f62'
    Author = 'Schvenn'
    CompanyName = 'Plath Consulting Incorporated'
    Copyright = '(c) Craig Plath. All rights reserved.'
    Description = 'Secure password manager using AES encryption and key-based protection.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('paschwords')
    CompatiblePSEditions = @('Desktop')
    
    # Configuration data
    PrivateData = @{
    delayseconds = '30'
    privilegedir = 'DefaultPowerShellDirectory\Modules\Paschwords\.privilege'
    archiveslimit = '5'
    databasedir = 'DefaultPowerShellDirectory\Modules\Paschwords\databases'
    keydir = 'DefaultPowerShellDirectory\Modules\Paschwords\keys'
    backupfrequency = '7'
    expirywarning = '365'
    logretention = '30'
    timeoutseconds = '900'
    defaultkey = 'paschwords.key'
    useragent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
    dictionaryfile = 'common.dictionary'
    logdir = 'DefaultPowerShellDirectory\Modules\Paschwords\logs'
    timetobootlimit = '60'
    defaultdatabase = 'paschwords.pwdb'
    }}

The script checks itself against a set of valid SHA256 hashes to ensure the file has not been modified.
A script "CheckNTPTime.ps1", ensures the system time hasn't been tampered with, in order to avoid user account expirations.
Another separate script "ValidateURLs.ps1" is included to test a file containing a list of URLs for connectivity. This is designed to be used with the Valid URLs search and export function within the module, but I am keeping it separate in order to ensure the Paschword manager remains completely offline and thereby limits its security exposure.
