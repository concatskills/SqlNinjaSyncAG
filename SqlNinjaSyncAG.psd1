@{

# Script module or binary module file associated with this manifest.
RootModule = 'SqlNinjaSyncAG.psm1'

# Version number of this module.
ModuleVersion = '1.0.6'

# ID used to uniquely identify this module
GUID = '5853366f-5d2e-4f04-982e-2aeab477f559'

# Author of this module
Author = 'Sarah BESSARD'

# Company or vendor of this module
CompanyName = 'Concat Skills'

# Copyright statement for this module
Copyright = '(c) 2018 Bessard S. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Synchronize secondaries replicas from primary for your avaibility group : logins, jobs, server roles, etc'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

        Queries = @{
        
            GetSysObjects = "SELECT	[Type] = 'Jobs', [name]
						    FROM [msdb].[dbo].[sysjobs] j
						    WHERE	name IN ('SSIS Failover Monitor Job', 'SSIS Server Maintenance Job')
                            OR		SUSER_SNAME(j.owner_sid) LIKE '##MS%' 
                            UNION ALL
                            SELECT	[Type] = 'Jobs', [name]
						    FROM [msdb].[dbo].[sysjobs] j
							CROSS APPLY (SELECT TOP 1 job_id FROM [msdb].[dbo].[sysjobsteps] s WHERE j.job_id = s.job_id AND s.server IS NOT NULL) s
                            UNION ALL
                            SELECT	[type] = 'Jobs', j.name
                            FROM	[msdb].[dbo].[sysjobs] j
                            INNER JOIN [msdb].[dbo].sysmaintplan_subplans sp ON sp.job_id = j.job_id
                            INNER JOIN [msdb].[dbo].sysmaintplan_plans p ON p.id = sp.plan_id
                            UNION ALL
                            SELECT	[Type] =
								    CASE WHEN [category_class] = 1 THEN 'JobCategories'
									    WHEN [category_class] = 2 THEN 'AlertCategories'
									    WHEN [category_class] = 3 THEN 'OperatorCategories'
								    END
							      ,[name]
						    FROM [msdb].[dbo].[syscategories]
						    WHERE	category_id < 100
						    UNION ALL
						    SELECT	Type = 'Roles', [name]
						    FROM	sys.server_principals
						    WHERE	1 = 1
						    AND		type = 'R'
						    AND		principal_id < 11
							UNION ALL
							SELECT	 [Type] = 'Logins', name
							FROM	sys.server_principals
							WHERE	type = 'C'
							OR		name LIKE 'NT SERVICE\%'
							OR		name LIKE 'NT AUTHORITY\%'
							OR		name LIKE ('BUILTIN\%')
						    UNION ALL
						    SELECT  DISTINCT [Type] = 'Logins', service_account
						    FROM    sys.dm_server_services"
            GetAdmGroups = "DECLARE @NtGroupMembers AS TABLE ( account_name SYSNAME, type CHAR(8), privilege CHAR(9), mapped_login_name SYSNAME, permission_path SYSNAME)

						    DECLARE @SqlDyn VARCHAR(MAX) 

						    SELECT	@SQLDyn =  
						    CAST(
								    (
									    SELECT	CONCAT('EXEC xp_logininfo ''',  name, ''' , ''members''')
									    FROM	sys.syslogins
									    WHERE	isntgroup = 1
									    AND		sysadmin = 1
									    AND 	name LIKE @@SERVERNAME + '\%'
									    FOR XML PATH(''), root('dynsql'), type 
								    ).value('/dynsql[1]', 'varchar(8000)') 
						    AS VARCHAR(8000)) 

						    --PRINT @SqlDyn
						    INSERT	INTO @NtGroupMembers
						    EXEC (@SqlDyn)

						    SELECT	COUNT(*) AS CntGroup
						    FROM	@NtGroupMembers
						    WHERE	mapped_login_name = '{0}'
						    AND		permission_path IN ({1})"
            DropLogins = "DECLARE @SQLDyn VARCHAR(MAX)

                            -- Kill & Disconnect
                            SET @SQLDyn = 
				                            ( 
					                            SELECT	DISTINCT 'KILL ' + CAST(session_id AS VARCHAR) + ';' + CHAR(10)  AS [text()]
					                            FROM	sys.dm_exec_sessions
					                            WHERE	login_name = '{0}'
					                            FOR XML PATH('')
				                            )	

                            EXEC (@SQLDyn)

                            DROP LOGIN [{0}]
                            GO"
            DropCredential = "DROP CREDENTIAL [{0}]
                             GO"
            CreateLogins = "SELECT	Name = s.name, 
		                            Type = s.type_desc,
		                            IsDisabled = s.is_disabled,
		                            CreateScript = IIF(s.type = 'S', 
				                            CONCAT('CREATE LOGIN ', QUOTENAME(s.name), ' WITH PASSWORD = ', CONVERT(varchar(MAX), LOGINPROPERTY(s.name, 'PasswordHash'),1), ' HASHED, SID = ', CONVERT(varchar(MAX), s.sid, 1), ', DEFAULT_DATABASE = ' , QUOTENAME(s.default_database_name), ', CHECK_POLICY = ', IIF(is_policy_checked = 1, 'ON', 'OFF'), ' , CHECK_EXPIRATION = ',  IIF(is_expiration_checked = 1, 'ON', 'OFF')), 
				                            CONCAT('CREATE LOGIN ', QUOTENAME(s.name), ' FROM WINDOWS WITH DEFAULT_DATABASE = ', QUOTENAME(IIF(d.name IS NOT NULL, s.default_database_name, 'master')))
				                            ) + CHAR(10) + 'GO'
                            FROM	sys.syslogins l
                            LEFT	JOIN sys.sql_logins q ON l.sid = q.sid
                            INNER	JOIN sys.server_principals s ON l.sid = s.sid
                            LEFT	JOIN sys.sysdatabases d ON s.default_database_name = d.name
                            WHERE	1 = 1
                            AND		s.name NOT LIKE '##MS_%'
                            AND		s.name NOT IN ('sa')"
            CreateCredential = "CREATE CREDENTIAL [{0}]  
                                    WITH IDENTITY='{1}', SECRET='<EnterStrongPasswordHere>'  
                                GO"

    } # End of Query hashtable

    ObjectToSync = 
    (
        @{
			Type =  "Logins"
			Scope = "Server"
			SortCreate = 1
			SortDrop = 2
        },
        @{
			Type = "Roles"
			Scope = "Server"
			SortCreate = 1
			SortDrop = 1
        },
        @{
			Type = "LinkedServers"
			Scope = "Server"
			SortCreate = 1
			SortDrop = 1
        },
        @{
			Type = "BackupDevices"
			Scope = "Server"
			SortCreate = 1
			SortDrop = 1
        },
        @{
			Type = "MemberRoles"
			Scope = "Server"
			SortCreate = 2
			SortDrop = 1
        },
        @{
			Type = "Permissions"
			Scope = "Server"
			SortCreate = 2
			SortDrop = 1
        },
		@{
			Type = "Credentials"
			Scope = "Server"
			SortCreate = 2
			SortDrop = 2
        },
		@{
			Type = "OperatorCategories"
			Scope = "JobServer"
			SortCreate = 1
			SortDrop = 2
        },
        @{
			Type = "AlertCategories"
			Scope = "JobServer"
			SortCreate = 1
			SortDrop = 2
        },
		@{
			Type = "JobCategories"
			Scope = "JobServer"
			SortCreate = 1
			SortDrop = 2
        },
		@{
			Type = "ProxyAccounts"
			Scope = "JobServer"
			SortCreate = 2
			SortDrop = 2
        },
        @{
			Type = "Operators"
			Scope = "JobServer"
			SortCreate = 3
			SortDrop = 1
        },		
        @{
			Type = "Alerts"
			Scope = "JobServer"
			SortCreate = 3
			SortDrop = 1
        },
        @{
			Type = "SharedSchedules"
			Scope = "JobServer"
			SortCreate = 1
			SortDrop = 2
        },
        @{
			Type = "Jobs"
			Scope = "JobServer"
			SortCreate = 3
			SortDrop = 1
        }

    );   

    }  # End of ObjectToSync hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
