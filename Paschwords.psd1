# Core module details
@{RootModule = 'Paschwords.psm1'
ModuleVersion = '3.8'
GUID = 'd4f71764-0e43-4632-8b35-0f0a79b36f62'
Author = 'Schvenn'
CompanyName = 'Plath Consulting Incorporated'
Copyright = '(c) Craig Plath. All rights reserved.'
Description = 'Secure password manager using AES encryption and key-based protection.'

# Compatibility
PowerShellVersion = '5.1'
CompatiblePSEditions = @('Desktop')

# Exported members
FunctionsToExport = @('paschwords')

# Configuration data
PrivateData = @{defaultkey = 'paschwords.key'
defaultdatabase = 'paschwords.pwdb'

# If you use some path under 'DefaultPowerShellDirectory', this portion of the path will be replaced in the script with the user's actual PowerShell directory.
keydir = 'DefaultPowerShellDirectory\Modules\Paschwords\keys'
databasedir = 'DefaultPowerShellDirectory\Modules\Paschwords\databases'

# timeoutseconds cannot exceed 99 minutes (5940 seconds)
timeoutseconds = '900'

# timetobootlimit cannot exceed 120 minutes.
timetobootlimit = '60'

# Clipboard clearance delay seconds before being wiped, provided the -noclip option is not already in use.
delayseconds = '30'

# This is the number of days that must pass before an entry's password is considered expired. The default and maximum is 365.
expirywarning = '365'

# logretention cannot be less than 30 days, but can be greater.
logretention = '30'

# Set the dictionary for password generation.
dictionaryfile = 'Common.dictionary'

# Set the scheduled backups frequency and limit.
backupfrequency = '7'
archiveslimit = '5'}}
