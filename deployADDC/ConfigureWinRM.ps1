#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the FQDN of machine or domain                                                           #
#################################################################################################################################

param
(
    [string] $hostname,
	[string] $svrAccountName,
	[string] $artificatsLocation="https://raw.githubusercontent.com/teradici/deploy/TSW-67106-use-external-ad/deployADDC",
	[Int32]	 $userCount=2500
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

function Delete-WinRMListener
{
    $config = Winrm enumerate winrm/config/listener
    foreach($conf in $config)
    {
        if($conf.Contains("HTTPS"))
        {
            Write-Output "HTTPS is already configured. Deleting the exisiting configuration."

            winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
            break
        }
    }
}

function Get-Thumbprint
{
    param([string] $hostname)

	$certLoc = 'cert:Localmachine\My'
    
    $thumbprint = (Get-ChildItem $certLoc | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1).Thumbprint
    
    $thumbprint
}

function Create-Certificate
{
    param([string] $hostname)

	# create self signed certificate
	$certLoc = 'cert:Localmachine\My'
  	$startDate = [DateTime]::Now.AddDays(-1)
  	$endDate = [DateTime]::Now.AddDays(365)
   	$subject = "CN=" + $hostname
   	$cert = New-SelfSignedCertificate -Type Custom -certstorelocation $certLoc -Subject $subject `
    		-NotBefore $startDate -NotAfter $endDate -KeySpec KeyExchange -KeyExportPolicy Exportable `
    		-Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    		-TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")  
    
    if(	$cert -eq $null)
    {
        throw "Failed to create the test certificate."
    }
    
    $cert
}

function Configure-WinRMHttpsListener
{
    param([string] $hostname)

    # Delete the WinRM Https listener if it is already configured
    Delete-WinRMListener

    $thumbprint = Get-Thumbprint($hostname)
    if($thumbprint -eq $null)
    {
    	$cert = Create-Certificate($hostname)

        $thumbprint =$cert.Thumbprint
    }	

    $winargs = '@{Hostname="'+$hostname+'";CertificateThumbprint="'+$thumbprint+'"}'
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS $winargs
}

function Add-FirewallException
{
    param([string] $port)

    # Delete an exisitng rule
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port

    # Add a new firewall rule
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port
}


function Delegate-Join-VM-Domain
{
    param([string] $saAccount)

    Write-Output "Grant join domain permissions to user ..."

	$domain = Get-ADDomain
	$ouDN = $domain.ComputersContainer

	$SearchAccount = Get-ADUser $saAccount
 
	$SAM = $SearchAccount.SamAccountName
	$UserAccount = $domain.NetBIOSName+"\"+$SAM
    
	dsacls.exe $ouDN /G $UserAccount":CCDC;Computer" /I:T | Out-Null
	dsacls.exe $ouDN /G $UserAccount":LC;;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":RC;;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WD;;Computer" /I:S  | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WP;;Computer" /I:S  | Out-Null
	dsacls.exe $ouDN /G $UserAccount":RP;;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":CA;Reset Password;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":CA;Change Password;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WS;Validated write to service principal name;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WS;Validated write to DNS host name;Computer" /I:S | Out-Null

    Write-Output "Finished to grant join domain permissions to user."
}

function addMembersToRemoteManagerUsersGroup
{
    param([string] $saAccount)

    Write-Output "Add member to Remote Management Users Group ... "
	$adUser = Get-ADUser $saAccount
	
	if ($adUser -eq $null) {
	    Write-Output "User [" + $saAccount + "] does not exist!" 
		throw "Failed to add user to 'Remote Management Users' group because the user [" + $saAccount + "] does not exist."
	}
	
    $adGroup = Get-ADGroup 'Remote Management Users'
	if ($adGroup -eq $null) {
	    Write-Output "The group [Remote Management Users] does not exist!"
		throw "Failed to add user to 'Remote Management Users' group because the group could not be found."
	}

    Add-ADGroupMember $adGroup.ObjectGUID -Members $adUser.ObjectGUID	

    Write-Output "Finished to add member to Remote Management Users Group."
}

function createGroupForCAM
{
    param([string] $saAccount)

    Write-Output "Create group 'Remote Workstations' ..." 

	$rwGroup = "Remote Workstations"
	$adUser = Get-ADUser $saAccount
	New-ADGroup -name $rwGroup -GroupScope Global -ManagedBy $adUser.DistinguishedName | Out-Null
	
	$domain = Get-ADDomain
	$SAM = $adUser.SamAccountName
	$UserAccount = $domain.NetBIOSName+"\"+$SAM

	Start-Sleep -Seconds 1

	$rwGroupObj = Get-ADGroup $rwGroup
	if ($rwGroupObj -eq $null) {
	    Write-Output "Failed to create the group [" + $rwGroup + "]."
		throw "Failed to create the group [" + $rwGroup + "]."
	}

	dsacls.exe $rwGroupObj.DistinguishedName /G $UserAccount":WP;member" /I:T | Out-Null

    Write-Output "Finished to create group." 
}



#################################################################################################################################
#                                              Configure WinRM                                                                  #
#################################################################################################################################

Import-Module ActiveDirectory

$winrmHttpsPort=5986

# Configure-WinRMHttpsListener $hostname

# Add-FirewallException -port $winrmHttpsPort

Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any | Out-Null

Delegate-Join-VM-Domain $svrAccountName
addMembersToRemoteManagerUsersGroup $svrAccountName
createGroupForCAM $svrAccountName

#################################################################################################################################
#################################################################################################################################


#################################################################################################################################
#                                              Create Random Users                                                              #
#################################################################################################################################

$domain=(Get-ADDomain).Forest

if (! $artificatsLocation.EndsWith('/')) {
    $artificatsLocation = $artificatsLocation + '/'
}
$scriptUrl = $artificatsLocation + "CreateUsers.ps1"

Invoke-WebRequest -UseBasicParsing -Uri $scriptUrl -OutFile CreateUsers.ps1

Write-Output "Starting to create users ..." 
.\CreateUsers.ps1 -userCount $userCount -dnsDomain $domain -baseUrl $artificatsLocation
Write-Output "Finished to create users" 
Write-Output "Completed execution" 
#################################################################################################################################
#################################################################################################################################
