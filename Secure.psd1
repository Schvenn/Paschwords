@{ModuleVersion = '3.1'
RootModule = 'Secure.psm1'
FunctionsToExport = @('pwmanage')
PrivateData = @{defaultkey="secure.key"
defaultdatabase="secure.pwdb"
keydir="DefaultPowerShellDirectory\Modules\Secure\keys"
databasedir="DefaultPowerShellDirectory\Modules\Secure\databases"
timeoutseconds="900"
delayseconds="30"
expirywarning="365"
logretention="30"}}
