# Core module details
@{
RootModule = 'Paschwords.psm1'
ModuleVersion = '4.6'
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
