# Core module details
@{
CompatiblePSEditions = @('Desktop')
CompanyName = 'Plath Consulting Incorporated'
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
}
ModuleVersion = '3.9'
Description = 'Secure password manager using AES encryption and key-based protection.'
GUID = 'd4f71764-0e43-4632-8b35-0f0a79b36f62'
Copyright = '(c) Craig Plath. All rights reserved.'
RootModule = 'Paschwords.psm1'
Author = 'Schvenn'
}
