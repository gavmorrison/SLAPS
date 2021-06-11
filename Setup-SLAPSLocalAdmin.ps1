<#
.DESCRIPTION
	This script will execute to setup a script in the ProgramData directory and a scheduled task to execute this daily
    Script being created and executed on schedule is based on 'New-LocalAdmin.ps1' from https://github.com/jseerden/SLAPS

.NOTES
	Author: Gavin Morrison, BCN Group
    Version: 1.0.0, June 2021
#>

# Variables to set
$companyName = ""
$localAdminUsername = "Administrator"
$azFunctionUri = ""
$maxPasswordAge = 30

#########################################################################
# DO NOT MAKE CHANGES BELOW HERE
#########################################################################
$scriptDir = "$( $env:ProgramData )\$( $companyName )\SLAPS"

# Create script directory if it does not exist and restrict access
#region setupScriptDir
if( -not( Test-Path $scriptDir ) )
{
    New-Item -path $scriptDir -type Directory | Out-Null
}

# Set permissions to restrict access to folder
$acl = Get-ACL $scriptDir
$acl.SetAccessRuleProtection( $true, $false )       # Params ( Disable Inheritance, Copy Permissions )

$identity = 'NT AUTHORITY\SYSTEM'
$rights = 'FullControl'                             # Other options: [enum]::GetValues('System.Security.AccessControl.FileSystemRights')
$inheritance = 'ContainerInherit, ObjectInherit'    # Other options: [enum]::GetValues('System.Security.AccessControl.Inheritance')
$propagation = 'None'                               # Other options: [enum]::GetValues('System.Security.AccessControl.PropagationFlags')
$type = 'Allow'                                     # Other options: [enum]::GetValues('System.Securit y.AccessControl.AccessControlType')
$ace = New-Object System.Security.AccessControl.FileSystemAccessRule( $identity, $rights, $inheritance, $propagation, $type )
$acl.AddAccessRule( $ace )

$identity = 'BUILTIN\Administrators'
$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule( $identity, $rights, $inheritance, $propagation, $type )
$acl.AddAccessRule( $ace )

Set-Acl -Path $scriptDir -AclObject $acl

#endregion setupScriptDir

# HERE STRING to define script that will be used for future password reset operations
#region scriptHereString
$scriptString = @'
# New-LocalUser is only available in a x64 PowerShell process. We need to restart the script as x64 bit first.
# Based on a template created by Oliver Kieselbach @ https://gist.github.com/okieselbach/4f11ba37a6848e08e8f82d9f2ffff516
$exitCode = 0

if (-not [System.Environment]::Is64BitProcess) {
    # start new PowerShell as x64 bit process, wait for it and gather exit code and standard error output
    $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"

    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.FileName = $sysNativePowerShell
    $processStartInfo.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $processStartInfo.RedirectStandardError = $true
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.CreateNoWindow = $true
    $processStartInfo.UseShellExecute = $false

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $process.Start()

    $exitCode = $process.ExitCode

    $standardError = $process.StandardError.ReadToEnd()
    if ($standardError) {
        Write-Error -Message $standardError 
    }
}
else {
    #region Configuration
    # Define the userName for the Local Administrator
    $userName = "«USERNAME»"

    # Define the max password age after whih the password will be reset
    $passwordMaxAge = "«PWMAXAGE»"

    # Azure Function Uri (containing "azurewebsites.net") for storing Local Administrator secret in Azure Key Vault
    $uri = '«FUNCTIONURI»'
    #endregion

    # Hide the $uri (containing "azurewebsites.net") from logs to prevent manipulation of Azure Key Vault
    $intuneManagementExtensionLogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
    if( Test-Path $intuneManagementExtensionLogPath ){ Set-Content -Path $intuneManagementExtensionLogPath -Value ( Get-Content -Path $intuneManagementExtensionLogPath | Select-String -Pattern "azurewebsites.net" -notmatch ) }

    # start logging to TEMP in file "scriptname.log"
    $null = Start-Transcript -Path "«LOGPATH»\$($(Split-Path $PSCommandPath -Leaf).ToLower().Replace(".ps1",".log"))"

    Function Get-NewPasswordFromFunction
    {
        # Azure Function Request Body. Azure Function will strip the keyName and add a secret value. https://docs.microsoft.com/en-us/rest/api/keyvault/setsecret/setsecret
        $body = @"
        {
            "keyName": "$env:COMPUTERNAME",
            "contentType": "Local Administrator Credentials",
            "tags": {
                "Username": "$userName"
            }
        }
"@

        # Use TLS 1.2 connection
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Trigger Azure Function.
        try {
            $password = Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop
        }
        catch {
            $exitCode = -1
            Write-Error "Failed to submit Local Administrator configuration. StatusCode: $($_.Exception.Response.StatusCode.value__). StatusDescription: $($_.Exception.Response.StatusDescription)"
            exit $exitCode
        }

        # Convert password to Secure String
        ConvertTo-SecureString $password -AsPlainText -Force
    }

    $accountAlreadyExists = $true
    # Check if userName already exists; if not create, otherwise check password agen age take appropriate action
    try {
        $account = Get-LocalUser -Name $userName -ErrorAction Stop
    
        if( $null -ne $account.PasswordLastSet ){ $pwAge = New-TimeSpan -Start $account.PasswordLastSet -End ( Get-Date ) }
        if( $null -eq $account.PasswordLastSet -or $pwAge -gt $passwordMaxAge )
        {
            $securePassword = Get-NewPasswordFromFunction
            Set-LocalUser -Name $userName -Password $securePassword
        }
    }
    catch {
        # Account needs to be created; set var for next section
        $accountAlreadyExists = $false
    }
    
    $accountAlreadyExists
    if( -not $accountAlreadyExists )
    {
        # Account not found; lets create it
        try
        {
            $securePassword = Get-NewPasswordFromFunction
            New-LocalUser -Name $userName -Password $securePassword -PasswordNeverExpires:$true -AccountNeverExpires:$true -ErrorAction Stop
            Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $userName
            Write-Output "Added Local User '$userName' to Local Administrators Group"
        }
        catch {
            $exitCode = -1
            Write-Error $_
        }
    }
    
    $null = Stop-Transcript
}

exit $exitCode
'@
#endregion scriptHereString

# Variable replace within $scriptString using variabled declared and output to working directory
#region outputNextScript
$scriptString = $scriptString.Replace( "«USERNAME»", $localAdminUsername ).Replace( "«PWMAXAGE»", $maxPasswordAge ).Replace( "«FUNCTIONURI»", $azFunctionUri ).Replace( "«LOGPATH»", $scriptDir )

$scriptString | Set-Content -Path "$( $scriptDir )\Set-LocalAdminPassword.ps1"

#endregion outputNextScript

# Setup Scheduled task to run the script daily
#region setupScheduledTask
$schtaskName = "Intune SLAPS"

# Check for existing Scheduled Task
try {
    $null = Get-ScheduledTask -TaskName $schtaskName -ErrorAction Stop
    Unregister-ScheduledTask -TaskName $schtaskName -Confirm:$false
}
catch {
    # No action required; task does not exist
}
$schtaskDescription = "Serverless LAPS account password reset"

$trigger = New-ScheduledTaskTrigger -Daily -At ( ( Get-Date -Hour 10 -Minute 0 -Second 0 ).AddSeconds( ( Get-Random -Minimum 0 -Maximum 14400 ) ) ).ToString( "HH:mm" )
#Execute task in users context
$principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -Id "LocalSystem" -RunLevel Highest
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoLogo -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$( $scriptDir )\Set-LocalAdminPassword.ps1`""
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -StartWhenAvailable -ExecutionTimeLimit ( New-TimeSpan -Hours 1 )

$null = Register-ScheduledTask -TaskName $schtaskName -Trigger $trigger -Action $action  -Principal $principal -Settings $settings -Description $schtaskDescription -Force

Start-ScheduledTask -TaskName $schtaskName
#endregion setupScheduledTask

