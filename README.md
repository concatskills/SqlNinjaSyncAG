# SqlNinjaSyncAG

# http://www.concatskills.com/2019/06/12/groupe-de-disponibilite-synchronisation-replicas-secondaires-jobs-logins-etc/
# Webcast : https://www.youtube.com/watch?v=pEYHOXxJuBs

Clear-Host

# Step 01 - Install 3 component from Microsoft SQL Server 2016 feature Pack
    ### SQLSysClrTypes.msi 
    ### SharedManagementObjects.msi 
    ### PowerShellTools.msi

# Step 02 - Allow PSGallery Repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Step 03 - Install module SqlNinjaSyncAG : Internet Access works on target machine
Install-Module -Name SqlNinjaSyncAG 

# Infos : Module PowerSHell locations
$env:PSModulePath.Split(";")

# Step 03 bis - Install module SqlNinjaSyncAG OFFLINE : Internet Access doesn't works on target machine
Save-Module –Name SqlNinjaSyncAG –Path C:\Download
Copy-Item "C:\Download\SqlNinjaSyncAG" -Destination "\\TARGETMACHINE\C$\Program Files\WindowsPowerShell\Modules" -Recurse

# Step 04 - Load module for current session
Import-Module -Name SqlNinjaSyncAG

# Step 05 - Create working directory for AG synchronization
$path = "C:\SyncAG"
If(!(test-path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}

# Step 06 - Create SQL login on all replicas and add it in sysadmin role
Invoke-Sqlcmd -ServerInstance SQLSRV01 -Database master -InputFile C:\TEMP\Login.sql
Invoke-Sqlcmd -ServerInstance SQLSRV02 -Database master -InputFile C:\TEMP\Login.sql

# Step 07 - Working directory to store encrypted password
Set-Location C:\TEMP

# Step 08 - Encrypt password for SQL login
Export-SqlNinjaEncryptedPwd -Username admsync -Password '!{JC26Mcp)WG=$:'

# Step 09 - Copy template file for configuration to C:\SyncAG
Copy-Item "C:\Program Files\WindowsPowerShell\Modules\SqlNinjaSyncAG\1.0.1\MyConf.json" -Destination C:\SyncAG 

### Generate T-SQL scripts synchronisation ###

Import-Module -Name SqlNinjaSyncAG -Force
Set-Location C:\SyncAG
Start-SqlNinjaSyncAG -InputFile MyConf.json -Execute $False

### Execute synchronisation ###

Import-Module -Name SqlNinjaSyncAG -Force
Set-Location C:\SyncAG
Start-SqlNinjaSyncAG -InputFile MyConf.json -Execute $True
