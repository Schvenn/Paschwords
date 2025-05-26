# Secure
PowerShell module to manage your passwords. Uses AES256 bit encryption with a PBKDF2 (Password-Based Key Derivation Function 2) master password.

    Usage: pwmanage <database.pwdb> <keyfile.key> -noclip

# Overview
If no database/keyfile are specified, the defaults "secure.pwdb" and "secure.key" will be used.

When a password is retrieved, it will automatically be copied to the clipboard for 30 seconds,
unless the -noclip option is used at launch time.

You can configure the default password, default key file and directories where these are saved
by modifying the entries in the "Secure.psd1" file located in the same directory as the module.

It is of course, best practice to save the key files somewhere distant from the databases.
You could even save the database files on cloud storage, but I recommended saving the keys locally.

The initial configurations of the directories within the PSD1 file point to:

"DefaultPowerShellDirectory\Modules\Secure\keys" and "DefaultPowerShellDirectory\Modules\Secure\databases".

The term "DefaultPowerShellDirectory" is a placeholder that is evaluated within the module,
redirecting these to your personal PowerShell directory. As stated above, I advise moving these
somewhere else once you've setup the database and plan to use it long-term.

# Background
I started this project when I realized that it was possible to create a JSON database with encrypted entries within PowerShell.
From there, it just made sense to create a full-fledged password manager.
The options required were obvious and the need for a master password was, as well.
I know this has very practical applications, because I work for clients who have systems that are extremely well locked down.
That means however, that they do not let you install unapproved software, but most will let you install PowerShell modules.
So, I created this module to be able to fill that niche.

In order to use this module the first time, you will either need to create databases and keys directories inside the module's directory,
or you will need to edit the PSD1 file to point these settings to a directory of your choosing.

    @{ModuleVersion = '1.0'
    RootModule = 'Secure.psm1'
    PrivateData = @{defaultkey="secure.key"
    defaultdatabase="secure.pwdb"
    keydir="DefaultPowerShellDirectory\Modules\Secure\keys"
    databasedir="DefaultPowerShellDirectory\Modules\Secure\databases"}}

As mentioned above, if you leave "DefaultPowerShellDirectory" in the configuration file, the module will redirect these for you.

# Initial Setup
A default database and keyfile have been included, with a single entry for demonstration purposes.
The key has no master password, which I of course don't recommend for real world use, but it will let you test out the functionality.
