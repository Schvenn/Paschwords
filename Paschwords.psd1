# Core module details
@{
RootModule = 'Paschwords.psm1'
ModuleVersion = '4.0'
GUID = 'd4f71764-0e43-4632-8b35-0f0a79b36f62'
Author = 'Schvenn'
CompanyName = 'Plath Consulting Incorporated'
Copyright = '(c) Craig Plath. All rights reserved.'
Description = 'Secure password manager using AES encryption and key-based protection.'
CompatiblePSEditions = @('Desktop')
FunctionsToExport = @('paschwords')
PowerShellVersion = '5.1'

# Configuration data
PrivateData = @{
databasedir = 'DefaultPowerShellDirectory\Modules\Paschwords\databases'
expirywarning = '365'
delayseconds = '30'
defaultdatabase = 'paschwords.pwdb'
timetobootlimit = '60'
dictionaryfile = 'common.dictionary'
privilegedir = 'DefaultPowerShellDirectory\Modules\Paschwords\.privilege'
timeoutseconds = '900'
logretention = '30'
useragent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
archiveslimit = '5'
backupfrequency = '7'
keydir = 'DefaultPowerShellDirectory\Modules\Paschwords\keys'
defaultkey = 'paschwords.key'
}}
