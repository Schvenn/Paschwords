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
useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}}
