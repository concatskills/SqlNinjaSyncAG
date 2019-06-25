#requires -version 3

function Invoke-SqlNinjaCmd
{
    <#
    .SYNOPSIS
        Runs a T-SQL script.
    .DESCRIPTION
        Runs a T-SQL script. Invoke-SqlNinjaCmd runs the whole script and only captures the first selected result set, such as the output of PRINT statements when -verbose parameter is specified.
        Parameterized queries are supported.    
    .NOTES
        File Name      : SqlNinjaSyncAG.psm1
        Author         : Sarah BESSARD (sarah.bessard@concatskills.com)
        Prerequisite   : PowerShell V5 over Vista and upper.
        Copyright 2018 - Sarah BESSARD / CONCAT SKILLS
    .LINK
        Script posted over:
        Company website : http://www.concatskills.com
        Github : https://github.com/concatskills
    .EXAMPLE
        Invoke-SqlNinjaCmd -ServerInstance SRVNAME\INSTANCENAME -UserName bidule -Password chouette -Database MyDb -Query "SELECT @@VERSION"
    #>

    [CmdletBinding()] 
    param( 
    [Parameter(Position=0, Mandatory=$true)] [string]$ServerInstance, 
    [Parameter(Position=1, Mandatory=$false)] [string]$Database, 
    [Parameter(Position=2, Mandatory=$false)] [string]$Query, 
    [Parameter(Position=3, Mandatory=$false)] [string]$Username, 
    [Parameter(Position=4, Mandatory=$false)] [string]$Password, 
    [Parameter(Position=5, Mandatory=$false)] [Int32]$QueryTimeout=600, 
    [Parameter(Position=6, Mandatory=$false)] [Int32]$ConnectionTimeout=15, 
    [Parameter(Position=7, Mandatory=$false)] [ValidateScript({test-path $_})] [string]$InputFile, 
    [Parameter(Position=8, Mandatory=$false)] [ValidateSet("Batch", "DataSet", "DataTable", "DataRow")] [string]$As="DataRow" 
    ) 
 
    if ($InputFile) 
    { 
        $filePath = $(resolve-path $InputFile).path 
        $Query =  [System.IO.File]::ReadAllText("$filePath") 
    } 
 
    $conn=new-object System.Data.SqlClient.SQLConnection 
      
    if ($Username) 
    { $ConnectionString = "Server={0};Database={1};User ID={2};Password={3};Trusted_Connection=False;Connect Timeout={4}" -f $ServerInstance,$Database,$Username,$Password,$ConnectionTimeout } 
    else 
    { $ConnectionString = "Server={0};Database={1};Integrated Security=True;Connect Timeout={2}" -f $ServerInstance,$Database,$ConnectionTimeout } 
 
    $conn.ConnectionString=$ConnectionString 
     
    #Following EventHandler is used for PRINT and RAISERROR T-SQL statements. Executed when -Verbose parameter specified by caller 
    if ($PSBoundParameters.Verbose) 
    { 
        $conn.FireInfoMessageEventOnUserErrors=$true 
        $handler = [System.Data.SqlClient.SqlInfoMessageEventHandler] {Write-Verbose "$($_)"} 
        $conn.add_InfoMessage($handler) 
    }  
     
    $conn.Open() 

    if ($As -eq "Batch") {

        $batches = $Query -split "GO\r\n"

        foreach($batch in $batches)
        {
            if ($batch.Trim() -ne ""){

                $cmd=new-object system.Data.SqlClient.SqlCommand($batch,$conn) 
                $cmd.CommandTimeout=$QueryTimeout
                $returnVal = $cmd.ExecuteNonQuery()

                if ($returnVal -ne -1)
                {
                    Write-Host ("Error in T-SQL sync : `n" + $batch)
                }


            }
        }

        $conn.Close()

    } 
    else 
    {

        $cmd=new-object system.Data.SqlClient.SqlCommand($Query,$conn) 
        $cmd.CommandTimeout=$QueryTimeout 

        $ds=New-Object system.Data.DataSet 
        $da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd) 
        [void]$da.fill($ds) 
        $conn.Close()

        switch ($As) 
        { 

            'DataSet'   { Write-Output ($ds) } 
            'DataTable' { Write-Output ($ds.Tables) } 
            'DataRow'   { Write-Output ($ds.Tables[0]) } 
        } 
    
    }
 
}

function Export-SqlNinjaEncryptedPwd
{

    <#
    .SYNOPSIS
        Encrypt SQL login password
    .DESCRIPTION
        Encrypt SQL login password 
    .NOTES
        File Name      : SqlNinjaSyncAG.psm1
        Author         : Sarah BESSARD (sarah.bessard@concatskills.com)
        Prerequisite   : PowerShell V5 over Vista and upper.
        Copyright 2018 - Sarah BESSARD / CONCAT SKILLS
    .LINK
        Script posted over:
        Company website : http://www.concatskills.com
        Github : https://github.com/concatskills
    .EXAMPLE
        Export-SqlNinjaEncryptedPwd -Username sqlaccounttosync 
    .EXAMPLE
        Export-SqlNinjaEncryptedPwd -Username sqlaccounttosync -Password MyPWD
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$False)] [string]$Username,
        [Parameter(Mandatory=$False)] [string]$Password
        )
     begin 
            {

                $ScriptDirectory = Get-Location
            }
    process
            {  

                if ([string]::IsNullOrEmpty($Username)) {
                    $Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                }

                if ([string]::IsNullOrEmpty($Password)) {
                    [System.Security.SecureString]$SecurePassword = Read-Host "Enter Password" -AsSecureString
                    [String]$Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword));
                }

                $FileName = "Pwd_" + $($env:USERNAME) + ".txt"

                $Secure = ConvertTo-SecureString $Password -force -asPlainText
                $bytes = ConvertFrom-SecureString $Secure
                $bytes | out-file $FileName

        }

}


function Start-SqlNinjaSyncAG
{

    <#
    .SYNOPSIS
        Synchronize Secondaries replicas in Availability Group or generate synchronization script for each replica
    .DESCRIPTION
        Synchronize Secondaries replicas in Availability Group or generate synchronization script for each replica
    .NOTES
        File Name      : SqlNinjaSyncAG.psm1
        Author         : Sarah BESSARD (sarah.bessard@concatskills.com)
        Prerequisite   : PowerShell V5 over Vista and upper.
        Copyright 2018 - Sarah BESSARD / CONCAT SKILLS
    .LINK
        Script posted over:
        Company website : http://www.concatskills.com
        Github : https://github.com/concatskills
    .EXAMPLE
        Start-SqlNinjaSyncAG -InputFile MyConf.json
        This command generate synchronisation script for each secondary replicas
    .EXAMPLE
        Start-SqlNinjaSyncAG -InputFile MyConf.json -Execute $True
        This command generate and execute synchronisation script for each secondary replicas
    .EXAMPLE
        Start-SqlNinjaSyncAG -InputFile MyConf.json -LogRetentionDays 5
        This command allow to change days retention for execution logs (3 days by default)
    #>

    [CmdletBinding()]
    param(
            [Parameter(Mandatory=$True)] [string]$InputFile,
            [Parameter(Mandatory=$False)] [bool]$Execute=$False,
            [Parameter(Mandatory=$False)] [int]$LogRetentionDays=3
        )
        begin 
        {

            $ScriptDirectory = Get-Location
            $ScriptDirectoryIn = $ScriptDirectory
            $ScriptDirectorySql = "$($ScriptDirectory)\sql"
            $ScriptDirectoryOut = "$($ScriptDirectory)\out"
            $ScriptDirectoryLog = "$($ScriptDirectory)\log\"
        
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | out-null
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | out-null
            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null

            #clear-host

        }
        process
        {  

            function ConvertTo-PsCustomObjectFromHashtable { 
                 param ( 
                     [Parameter(  
                         Position = 0,   
                         Mandatory = $true,   
                         ValueFromPipeline = $true,  
                         ValueFromPipelineByPropertyName = $true  
                     )] [object[]]$hashtable 
                 ); 
     
                 begin { $i = 0; } 
     
                 process { 
                     foreach ($myHashtable in $hashtable) { 
                         if ($myHashtable.GetType().Name -eq 'hashtable') { 
                             $output = New-Object -TypeName PsObject; 
                             Add-Member -InputObject $output -MemberType ScriptMethod -Name AddNote -Value {  
                                 Add-Member -InputObject $this -MemberType NoteProperty -Name $args[0] -Value $args[1]; 
                             }; 
                             $myHashtable.Keys | Sort-Object | % {  
                                 $output.AddNote($_, $myHashtable.$_);  
                             } 
                             $output; 
                         } else { 
                             Write-Warning "Index $i is not of type [hashtable]"; 
                         } 
                         $i += 1;  
                     } 
                 } 
            }

            function GetServer
            {
                Param(
                    [Parameter(Mandatory=$True)][string]$Instance,
                    [Parameter(Mandatory=$False)][string]$Login,
                    [Parameter(Mandatory=$False)][string]$Password
                )
                begin {}
                process
                {

                    $Conn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection
                    $Conn.ServerInstance=$Instance

                    $Server = New-Object Microsoft.SqlServer.Management.Smo.Server($Conn)
                    if (![string]::IsNullOrEmpty($Login)) {
                        $Server.ConnectionContext.LoginSecure = $false
                        $Server.ConnectionContext.Login=$Login
                        $Server.ConnectionContext.Password=$Password
                    }

                    return $Server 
                }
                end {}
            }

            function AddExclusions
            {
                Param(
                    [Parameter(Mandatory=$True)][string]$ObjectType,
                    [Parameter(Mandatory=$False)][string[]]$UserExclusions,
                    [Parameter(Mandatory=$False)][Object[]]$SystemExclusions
                )
                begin {}
                process
                {

                    # Manage exclusions
                    $Exclusions = @()
                    # Custom exclusions
                    [string[]]$NewUserExclusions = $UserExclusions | sort -Unique
                    # System exclusion
                    [string[]]$NewSystemExclusions = $SystemExclusions | Where-Object { $_.Type -eq $ObjectType } | Foreach { "$($_.Name)" }

                    $Exclusions = $NewUserExclusions + $NewSystemExclusions

                    return $Exclusions 
                }
                end {}
            }

            try
            {          

                $InputFile = "$($ScriptDirectoryIn)\$($InputFile)"

                $LogRetentionDays = [System.Math]::Abs($LogRetentionDays) * (-1)
                $LogFile = $ScriptDirectoryLog + "sync_" + (Get-Date -format 'yyyyMMdd_HHmmss') + "_" + ([System.IO.Path]::GetFileNameWithoutExtension($InputFile)) + ".log"

                ######################
                ### Initialization ###
                ###################### 

                if (($PSVersionTable.PSVersion.Major) -ge 4){
                    Start-Transcript -path $LogFile
                }

                If(!(test-path $ScriptDirectoryOut)) { New-Item -ItemType Directory -Force -Path $ScriptDirectoryOut } else { Get-ChildItem -Path $ScriptDirectoryOut -Include *.* -Recurse  | remove-Item -Recurse -Force }

                Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - FILESYSTEM -> Clean-up 'out' directory")
    
                If(!(test-path $ScriptDirectoryLog)) { 
                    New-Item -ItemType Directory -Force -Path $ScriptDirectoryOut
                    Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - FILESYSTEM -> Create up 'log' directory")
                } else 
                { 
                    $limit = (Get-Date).AddDays($LogRetentionDays)

                    Get-ChildItem $ScriptDirectoryLog -Recurse | ? {
                      -not $_.PSIsContainer -and $_.CreationTime -lt $limit
                    } | Remove-Item -Force 
                    Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - FILESYSTEM -> Clean-up 'log' directory")
                }

                Import-LocalizedData -BaseDirectory $PSScriptRoot  -BindingVariable Data

                $Queries = $Data.PrivateData.Queries

                $ConfObjToSync = ConvertTo-PsCustomObjectFromHashtable ($Data.PrivateData.ObjectToSync)

                $ScriptCreateLogins = $Queries.CreateLogins
                $ScriptDropLogins = $Queries.DropLogins
                $ScriptCreateCredentials = $Queries.CreateCredentials
                $ScriptDropCredentials = $Queries.DropCredentials
                $ScriptGetSysObjects = $Queries.GetSysObjects
                $ScriptGetAdmGroups = $Queries.GetAdmGroups
                $ScriptDropInstanceObjects = "$($ScriptDirectoryOut)\01 - drop_instance_objects.sql"
                $ScriptCreateInstanceObjects = "$($ScriptDirectoryOut)\02 - create_instance_objects.sql"

                $json = (Get-Content $InputFile -Raw) | ConvertFrom-Json

                Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - FILESYSTEM -> Get content from configuration file : " + $InputFile)

                # AvaibilityGroup Infos
                $AvaibilityGroup = $json.AvaibilityGroup
                # Fix Owner : transfer to sa
                # Replicas Exclusions
                $ReplicasExclusions = $json.Replicas.Exclusions
                # Job : First Step Name for AG
                $FirstStepNameCheck = $json.Jobs.FirstStepNameCheck

                # Objects to synchronize
                $ObjToSync = $json.Objects
                # Logins to keep to be safe

                $out = $null

                if ([bool]::TryParse($json.FixOwner, [ref]$out)) {
                    $FixOwner = $out
                } else {
                    $FixOwner = $False
                }

                if ([bool]::TryParse($json.Jobs.ExcludeIfNoCheck, [ref]$out)) {
                    $ExcludeIfNoCheck = $out
                } else {
                    $ExcludeIfNoCheck = $False
                }
  
                # Add System Properties to ObjToSync
                ForEach($obj in $ObjToSync){

                    $out = $null

                    if ([bool]::TryParse($obj.ToSync, [ref]$out)) {
                        $obj.ToSync = $out
                    } else {
                        $obj.ToSync = $False
                    }

                   $obj | Add-Member -MemberType NoteProperty -Name "Scope" -Value ($ConfObjToSync | Where-Object { $_.Type -eq  $obj.Type }).Scope
                   $obj | Add-Member -MemberType NoteProperty -Name "SortDrop" -Value ($ConfObjToSync | Where-Object { $_.Type -eq  $obj.Type }).SortDrop
                   $obj | Add-Member -MemberType NoteProperty -Name "SortCreate" -Value ($ConfObjToSync | Where-Object { $_.Type -eq  $obj.Type } ).SortCreate

                }

                if (![string]::IsNullOrEmpty($AvaibilityGroup.Login) -And [string]::IsNullOrEmpty($AvaibilityGroup.Password)) {
                    [System.Security.SecureString]$SecurePassword = Read-Host "Enter Password" -AsSecureString
                    [String]$AvaibilityGroup.Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword));
                } elseif (![string]::IsNullOrEmpty($AvaibilityGroup.Login) -And ![string]::IsNullOrEmpty($AvaibilityGroup.Password)) {
                    $SecurePwd =  $AvaibilityGroup.Password | ConvertTo-SecureString
                    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $AvaibilityGroup.Login, $SecurePwd
                    $AvaibilityGroup.Password = ($credential.GetNetworkCredential()).Password
                }

                $WindowsLogin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                if ([string]::IsNullOrEmpty($AvaibilityGroup.Login)) 
                { 
                    $CheckWindowsLogin = $True
                    $SafeLoginsExclusion = @('sa',$WindowsLogin) 
                }
                else 
                { 
                    $CheckWindowsLogin = $False
                    $SafeLoginsExclusion = @('sa',$AvaibilityGroup.Login) 
                }

                # Logins to exclude : NT SERVICE, NT AUTHORITY, local MACHINE, etc
                $LoginRegex = "^({0})\\.*$"
                # Scripts to exclude for clean up
                $ScriptRegex = "^(sync_|02 - create_instance_objects).*$"
                # Batch separator in T-SQL scripts
                $BatchSeperator = "`r`nGO"

                $My = "Microsoft.SqlServer.Management.Smo"

                # Primary Replica
                $ScriptOptionsCreate = new-object ("$My.ScriptingOptions")
                $ScriptOptionsCreate.ContinueScriptingOnError = $true
                $ScriptOptionsCreate.ScriptBatchTerminator = $true
                $ScriptOptionsCreate.IncludeHeaders = $true
                $ScriptOptionsCreate.ToFileOnly = $true
                $ScriptOptionsCreate.IncludeIfNotExists = $false
                $ScriptOptionsCreate.Filename =  $ScriptCreateInstanceObjects
                $ScriptOptionsCreate.AppendToFile =  $true

                # Secondaries Replicas
                $ScriptOptionsDrop = new-object ("$My.ScriptingOptions")
                $ScriptOptionsDrop.ContinueScriptingOnError = $true
                $ScriptOptionsDrop.ScriptBatchTerminator = $true
                $ScriptOptionsDrop.IncludeHeaders = $true
                $ScriptOptionsDrop.ToFileOnly = $true
                $ScriptOptionsDrop.IncludeIfNotExists = $true
                $ScriptOptionsDrop.Filename =  $ScriptDropInstanceObjects
                $ScriptOptionsDrop.AppendToFile =  $true
                $ScriptOptionsDrop.ScriptDrops = $true

                $PrimaryReplica = GetServer -Instance $AvaibilityGroup.Listener -Login $AvaibilityGroup.Login -Password $AvaibilityGroup.Password

                Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - PRIMARY REPLICA " + $PrimaryReplica.Name + " -> Connecting to " + $AvaibilityGroup.Listener)
    
                if ($PrimaryReplica.AvailabilityGroups -eq $null) 
                {
                    Write-Error "!!! Connection fails !!!"
                }
                elseif ([string]::IsNullOrEmpty($PrimaryReplica.AvailabilityGroups)) 
                {         
                    Write-Error "!!! None Availability Group on this instance !!!" 
                } 
                else
                { 

                    $AllReplicas = $PrimaryReplica.AvailabilityGroups | Where-Object { $_.Name -eq $AvaibilityGroup.Name } | Select-Object -ExpandProperty AvailabilityReplicas | Where-Object { $_.ConnectionState -eq "Connected" }

                    Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - PRIMARY REPLICA " + $PrimaryReplica.Name + " -> Get all replicas : " + $AllReplicas.Count + " replica(s) found" )

                    $SrvPrimaryReplica = ($AllReplicas | Where-Object { $_.Role -eq "Primary" } | Select -ExpandProperty Name).Split("\")[0]

                    Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - PRIMARY REPLICA " + $PrimaryReplica.Name + " -> Get primary replica Name")

                    ############################################
                    ### PRIMARY REPLICA : Get system objects ###
                    ############################################

                    $SysObjects = Invoke-SqlNinjaCmd -ServerInstance $AvaibilityGroup.Listener -Username $AvaibilityGroup.Login -Password $AvaibilityGroup.Password -Database master -Query $ScriptGetSysObjects -As DataRow 

                    #################################################################################
                    ### PRIMARY REPLICA : Generate script to CREATE Server Objects &  Server Jobs ###
                    #################################################################################

                     # Get SharedSchedules from Jobs exclusions
                    $ExcludedJobs = AddExclusions -ObjectType "Jobs" -UserExclusions ($ObjToSync | Where-Object { $_.ToSync -eq $True -And $_.Type -eq "Jobs" }).Exclusions -SystemExclusions $SysObjects
                    $ExcludedSharedSchedules = @()
                    $SQLAgent = $PrimaryReplica.JobServer.Jobs | Where-Object { $_.Name -in $ExcludedJobs } | % { 
                        $ExcludedSharedSchedules += $_.JobSchedules
                    }
                            
                    # Add SharedSchedules exclusions from Jobs exclusions
                    $ObjToSync | Where-Object { $_.Type -eq "SharedSchedules" } | % { 
                        $_.Exclusions = $_.Exclusions + $ExcludedSharedSchedules
                    }

                    foreach ($Item in $ObjToSync | Sort-Object -Property SortCreate) {

                        if ($Item.ToSync -eq $True) {
           
                            $Exclusions = AddExclusions -ObjectType $Item.Type -UserExclusions $Item.Exclusions -SystemExclusions $SysObjects

                            $Objects = if ($Item.Scope -eq "Server") { $PrimaryReplica.$($Item.Type) } elseif ($Item.Scope -eq "JobServer") { $PrimaryReplica.JobServer.$($Item.Type) } 
                            $Objects = $Objects | Where-Object { $_.name -notin $Exclusions }

                            Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - PRIMARY REPLICA " + $PrimaryReplica.Name + " -> Generate creation script for " + $Item.Type + " (SortCreate : "+ $Item.SortCreate +")")

                            switch ($Item.Type) 
                            { 
                                "Logins" 
                                {                               
                        
                                    ######################################################################################
                                    ### PRIMARY REPLICA : Generate script to CREATE logins with sid & crypted password ###
                                    ######################################################################################

                                    $LoginResult = Invoke-SqlNinjaCmd -ServerInstance $AvaibilityGroup.Listener -Username $AvaibilityGroup.Login -Password $AvaibilityGroup.Password -Database master -Query $ScriptCreateLogins -As DataRow

                                    ##################################################################################################
                                    ### PRIMARY REPLICA : Check exclusions for groups if Windows login is not existing on instance ###
                                    ##################################################################################################

                                    if ($CheckWindowsLogin) 
                                    {
                                        if (($LoginResult | Where-Object {!$_.IsDisabled -And $_.Name -eq $WindowsLogin }).Count -eq 0)
                                        {                                       
                                            $GroupsIn = "'" + ([system.String]::Join("','", $Exclusions)) + "'"
                                            $CustomScriptGetAdmGroups = $ScriptGetAdmGroups -f $WindowsLogin, $GroupsIn

                                            $Group = (Invoke-SqlNinjaCmd -ServerInstance $AvaibilityGroup.Listener -Username $AvaibilityGroup.Login -Password $AvaibilityGroup.Password -Database master -Query $CustomScriptGetAdmGroups -As DataRow).CntGroup

                                            if ($Group -eq 0) 
                                            {
                                                Throw "Your are currently logged as $WindowsLogin that seems member of group. Add its group in logins exclusions and check if group is sysadmin !"
                                            }
                                        }
                                    }

                                    $CustomLoginRegex = $LoginRegex -f $SrvPrimaryReplica

                                    $Objects = $LoginResult | Where-Object {!$_.IsDisabled -And $_.Name -notmatch $CustomLoginRegex -And $_.Name -notin $SafeLoginsExclusion -And $_.Name -notin $Exclusions }
                                    $Objects | Select-Object -ExpandProperty CreateScript | Out-File $ScriptCreateInstanceObjects
                                    $Logins = $Objects | Select -ExpandProperty Name 

                                } 
                                "Credentials"
                                {

                                   $CustomScriptCreateCredentials = $ScriptCreateCredentials
                            
                                   foreach ($Object in $Objects) 
                                   {
                                        $CustomScriptCreateCredentials -f $Object.Name, $Object.Identity | Out-File $ScriptCreateInstanceObjects -Append
                                   }

                                }
                                "MemberRoles"
                                {
                        
                                    ########################################################################
                                    ### PRIMARY REPLICA : Generate script to CREATE Server Roles Members ###
                                    ########################################################################

                                    foreach ($Role in $PrimaryReplica.Roles) 
                                    { 
                                        $Role.EnumServerRoleMembers() | Where-Object { $_ -in $Logins -And $_ -notmatch "^($SrvPrimaryReplica)\\.*$" } |% { 
                                            "EXEC master..sp_addsrvrolemember @loginame = N'{0}', @rolename = N'{1}'{2}" -f ($_,$Role.Name, $BatchSeperator) | Out-File $ScriptCreateInstanceObjects -Append
                                        }
                                    };
                                }
                                "Permissions"
                                {
                        
                                    #############################################################################
                                    ### PRIMARY REPLICA : Generate script to CREATE Server Object Permissions ###
                                    #############################################################################
                        
                                    $PrimaryReplica.EnumObjectPermissions() | Where-Object { $_.Grantee -in $Logins -And @("sa","dbo","information_schema","sys") -notcontains $_.Grantee -And $_.Grantee -notmatch "^(NT SERVICE|NT AUTHORITY|$SrvPrimaryReplica)\\.*$" } |% {
                                        if ($_.PermissionState -eq "GrantWithGrant") { $wg = "WITH GRANT OPTION"} else { $wg = ""};
                                        "{0} {1} ON {2}::[{3}] TO [{4}] {5}{6}" -f ($_.PermissionState.ToString().Replace("WithGrant","").ToUpper(),$_.PermissionType,$_.ObjectClass.ToString().ToUpper(),$_.ObjectName,$_.Grantee,$wg,$BatchSeperator) | Out-File $ScriptCreateInstanceObjects -Append
                                    };

                                }
                                "Jobs"
                                {
                                    foreach ($Object in $Objects) 
                                    {
                                        $JobSteps = $Object.JobSteps | Where-Object { $_.ID -eq 1 -And $_.Name -eq $FirstStepNameCheck } | Select-Object
                                        if ($JobSteps -eq $null) {  Write-Host ((" " * 24) + "Job without AG Check : " + $Object.Name + " - [Enabled = " + $Object.IsEnabled + "]" ) } 
                                        if ($ExcludeIfNoCheck -eq $False -Or $JobSteps -ne $Null) { $Object.Script($ScriptOptionsCreate) }                     
                                    }

                                }
                                default 
                                {
                                    foreach ($Object in $Objects) 
                                    {   
                                        $Object.Script($ScriptOptionsCreate)
                                    }
                                }
                            }

                        }

                    }

                    #################################
                    ### Find secondaries replicas ###
                    #################################

                    $SecondariesReplicas = $AllReplicas | Where-Object { $_.Role -eq "Secondary" -And $_.Name -notin $ReplicasExclusions }

                    Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - PRIMARY REPLICA " + $PrimaryReplica.Name + " -> Get secondaries replicas : " + $SecondariesReplicas.Count + " replica(s) found")

                    ######################################
                    ### SECONDARIES REPLICAS : Parsing ###
                    ######################################

                    foreach ($SecondaryReplica in $SecondariesReplicas) {

                        # Remove generated DropScript for previous secondary replica
                        If((test-path $ScriptDropInstanceObjects)) { Remove-Item -Force $ScriptDropInstanceObjects }

                        $SrvSecondaryReplica = ($SecondaryReplica.Name).Split("\")[0]

                        try
                        {

                            $SecondaryReplica = GetServer -Instance $SecondaryReplica.Name -Login $AvaibilityGroup.Login -Password $AvaibilityGroup.Password

                            Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - SECONDARY REPLICA " + $SecondaryReplica.Name + " -> Connecting to " + $SecondaryReplica.Name)

                            #################################################################################
                            ### SECONDARY REPLICA : Generate script to DROP Server Objects &  Server Jobs ###
                            #################################################################################
                        
                            # Availibility Group owner to sa
                            if ($FixOwner) 
                            {
                                "ALTER AUTHORIZATION ON AVAILABILITY GROUP::[{0}] TO sa{1}" -f $AvaibilityGroup.Name, $BatchSeperator | Out-File $ScriptDropInstanceObjects -Append
                            }

                            # Get Operators from Agent FailSafeOperator to exclude
                            $ExcludedOperator = $SecondaryReplica.JobServer.AlertSystem.FailSafeOperator

                            # Add SharedSchedules exclusions from Jobs exclusions
                            $ObjToSync | Where-Object { $_.Type -eq "Operators" } | % { 
                                $_.Exclusions = $_.Exclusions + $ExcludedOperator
                            }
                        
                            foreach ($Item in $ObjToSync | Sort-Object -Property SortDrop) {

                                if ($Item.ToSync -eq $True) {

                                    $Exclusions = AddExclusions -ObjectType $Item.Type -UserExclusions $Item.Exclusions -SystemExclusions $SysObjects

                                    $Objects = if ($Item.Scope -eq "Server") { $SecondaryReplica.$($Item.Type) } elseif ($Item.Scope -eq "JobServer") { $SecondaryReplica.JobServer.$($Item.Type) } 
                                    $Objects = $Objects | Where-Object { $_.name -notin $Exclusions }

                                    switch ($Item.Type) 
                                    {

                                        "Logins" 
                                        {
                                        
                                            #######################################################################################
                                            ### SECONDARY REPLICA : Generate script to kill/disconnect sessions and DROP logins ###
                                            #######################################################################################

                                            $CustomScriptDropLogins = $ScriptDropLogins
                                            $CustomLoginRegex = $LoginRegex -f $SrvSecondaryReplica

                                            $Objects = $Objects | Where-Object {!$_.IsDisabled -And $_.Name -notmatch $CustomLoginRegex -And $_.Name -notin $SafeLoginsExclusion }
                                            $Logins = $Objects | Select -ExpandProperty Name 
                            
                                            foreach ($Object in $Objects) 
                                            {
                                                $CustomScriptDropLogins -f $Object.Name | Out-File $ScriptDropInstanceObjects -Append
                                            }
                                
                                        }
                                        "Permissions"
                                        {
                        
                                            #########################################################################
                                            ### SECONDARY REPLICA : Generate script to CHANGE OWNER Server Object ###
                                            #########################################################################
                                        
                                            if ($FixOwner) 
                                            {
                                                $SecondaryReplica.EnumObjectPermissions() | Where-Object { $_.Grantor -in $Logins -And $_.Grantor -notmatch "^(NT SERVICE|NT AUTHORITY|$SrvSecondaryReplica)\\.*$" } |% {
                                                    "ALTER AUTHORIZATION ON {0}::[{1}] TO [sa]; {2}" -f ($_.ObjectClass.ToString().ToUpper(),$_.ObjectName,$BatchSeperator) | Out-File $ScriptDropInstanceObjects -Append
                                                 };
                                            }

                                        }
                                        "Credentials"
                                        {

                                           $CustomScriptDropCredentials = $ScriptDropCredentials
                            
                                           foreach ($Object in $Objects) 
                                           {
                                                $CustomScriptDropCredentials -f $Object.Name | Out-File $ScriptDropInstanceObjects -Append
                                           }

                                        }
                                        default 
                                        {
                                            foreach ($Object in $Objects) 
                                            { 
                                                $Object.Script($ScriptOptionsDrop) 
                                            } 
                                        }
                                    }
                    
                                }

                                Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - SECONDARY REPLICA " + $SecondaryReplica.Name + " -> Generate drop script for " + $Item.Type + " (SortDrop : "+ $Item.SortDrop +")")

                            }

                            #####################################################
                            ### Merge SQL files to apply on secondary replica ###
                            #####################################################
        
                            # Define name for synchronization script 
                            $ScriptToApply = "$($ScriptDirectoryOut)\sync_$($SrvSecondaryReplica).sql"

                            # Merge sql files into synchronization script 
                            Get-ChildItem -path $ScriptDirectoryOut -recurse |?{ ! $_.PSIsContainer } |?{($_.name).contains(".sql") -And $_.Name -notlike "sync_*" } | %{ Out-File -filepath $ScriptToApply -inputobject (get-content $_.fullname) -Append }

                            # Clean-up sql files after merge
                            Get-ChildItem -Path $ScriptDirectoryOut -Include *.sql* -Recurse -File | Where-Object { $_.Name -notmatch $ScriptRegex } | remove-Item -Force

                            Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - FILESYSTEM -> Create Synchronization script for secondary repliqua " + $SecondaryReplica.Name + " : " + $ScriptToApply)

                            if ($Execute) {

                                ########################################################
                                ### PRIMARY REPLICA : Change Owner for all databases ###
                                ########################################################

                                if ($FixOwner) 
                                {

                                    $PrimaryReplica = GetServer -Instance $PrimaryReplica.Name -Login $AvaibilityGroup.Login -Password $AvaibilityGroup.Password

                                    foreach ($db in $PrimaryReplica.Databases)
                                    {
                                        if ($db.Owner -ne "sa")
                                        { 
                                            $db.SetOwner("sa", $True)
                                            $db.Alter()
                                            Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - PRIMARY REPLICA " + $PrimaryReplica.Name + " -> Change Owner (" + $db.Owner +") to sa on database " + $db.Name)
                                        }
                                    }

                                }

                                ########################################################
                                ### SECONDARY REPLICA : Apply synchronization script ###
                                ########################################################

                                Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - SECONDARY REPLICA " + $SecondaryReplica.Name + " -> Launching Synchronization...")

                                Invoke-SqlNinjaCmd -ServerInstance "$($SecondaryReplica.Name)" -Username "$($AvaibilityGroup.Login)" -Password "$($AvaibilityGroup.Password)" -Database master -QueryTimeout 0 -InputFile "$($ScriptToApply)" -verbose -As Batch

                                Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - SECONDARY REPLICA " + $SecondaryReplica.Name + " -> Synchronization done")

                                #####################################################
                                ### SECONDARY REPLICA : Change Owner for all jobs ###
                                #####################################################

                                if ($FixOwner) 
                                {

                                    # Post synchronisation : init SMO
                                    $SecondaryReplica = GetServer -Instance $SecondaryReplica.Name -Login $AvaibilityGroup.Login -Password $AvaibilityGroup.Password
                
                                    $SQLAgent = $SecondaryReplica.JobServer;
                                    $SQLAgent.Jobs | Where-Object { $_.OwnerLoginName -ne "sa" -And $_.OwnerLoginName -notlike "##*" } | % { 
                                      $_.set_OwnerLoginName("sa")
                                      $_.Alter()
                                      Write-Host ((Get-Date -format 'yyyy-MM-dd HH:mm:ss') + " - SECONDARY REPLICA " + $SecondaryReplica.Name + " -> Change Owner to sa on job " + $_.Name)
                                      }

                                }
                            }
            
                        }
                        Catch
                        {   
                          $errorMessage = $_.Exception.Message
                          $line = $_.InvocationInfo.ScriptLineNumber
                          Write-Error "Error occurred on line $line : $ErrorMessage" 
                        }

                    }

                }

                If(test-path $ScriptCreateInstanceObjects) { remove-Item $ScriptCreateInstanceObjects -Force }

            }
            Catch
            {   
                $errorMessage = $_.Exception.Message
                $line = $_.InvocationInfo.ScriptLineNumber
                Write-Error "Error occurred on line $line : $ErrorMessage" 
            }
            Finally
            {
                if (($PSVersionTable.PSVersion.Major) -ge 4){
                    Stop-Transcript
                }
            }

    }

}