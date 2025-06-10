# Paschwords
PowerShell module to manage your passwords. 

    • The Key files use AES-256-CBC encryption, with a PBKDF2-derived key from the master paschword. A random IV is generated for each key file and prepended to the encrypted content.
    • The paschword entries are encrypted using AES-256-CBC with a random IV. The ciphertext is also Base64-encoded for storage.
    • The database files are serialized to JSON, compressed with GZIP, then prepended with the AES IV, encrypted using AES-256-CBC, and finally Base64-encoded.

    Usage: pwmanage <database.pwdb> <keyfile.key> -noclip

# Overview
If no database/keyfile are specified, the defaults "paschwords.pwdb" and "paschwords.key" will be used.

When a password is retrieved, it will automatically be copied to the clipboard for 30 seconds, unless the -noclip option is used at launch time.

You can configure and number of options by modifying the entries in the "Paschwords.psd1" file located in the same directory as the module, including the default password database filename, default key file and the directories where these are saved, as well as several other features.

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

    @{ModuleVersion = '3.8'
    RootModule = 'Paschwords.psm1'
    FunctionsToExport = @('paschwords')
    PrivateData = @{defaultkey="paschwords.key"
    defaultdatabase="paschwords.pwdb"
    # If you use some path under DefaultPowerShellDirectory, this will be replaced in the script with the user's actual PowerShell directory.
    keydir="DefaultPowerShellDirectory\Modules\Paschwords\keys"
    databasedir="DefaultPowerShellDirectory\Modules\Paschwords\databases"
    # timeoutseconds cannot exceed 99 minutes (5940 seconds)
    timeoutseconds="900"
    # timetobootlimit cannot exceed 120 minutes.
    timetobootlimit="60"
    # Clipboard clearance delay seconds before being wiped, provided the -noclip option is not already in use.
    delayseconds="30"
    # This is the number of days that must pass before an entry's password is considered expired. The default and maximum is 365.
    expirywarning="365"
    # logretention cannot be less than 30 days.
    logretention="30"
    # Set the dictionary for password generation.
    dictionaryfile="Common.dictionary"}}

As mentioned above, if you leave "DefaultPowerShellDirectory" in the configuration file, the module will redirect these for you.
