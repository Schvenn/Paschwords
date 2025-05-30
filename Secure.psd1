@{ModuleVersion = '2.8'
RootModule = 'Secure.psm1'
FunctionsToExport = @('pwmanage')
PrivateData = @{defaultkey="secure.key"
defaultdatabase="secure.pwdb"
keydir="DefaultPowerShellDirectory\Modules\Secure\keys"
databasedir="DefaultPowerShellDirectory\Modules\Secure\databases"
delayseconds="30"}}
