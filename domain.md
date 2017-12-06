Deploy CAM with existing Active Directory Domain Controller
==========================================================

In order to deploy CAM integrated with a pre-existing domain controller, the following parameters have to be provided:  
* **domain name** the name of the domain the VM will join
* **domain group name** the name of domain group that VM will be added to
* **service account name** a service account which has sufficent permissions to join computer to a domain, a domain group and use remote powershell to the  domain controller 
* **service account password** password for the service account
* **Virtual NetWork Id** the id of the virtual network where CAM will be deployed
* **Subnet for remote workstations** the subnet where the remote workstations will be deployed
* **Subnet for Azure Application Gateway** the subnet where the CAM Azure Application Gateway will be deployed. Note this subnet cannot have any other resources than application gateways.

> **Notes** It assumes CAM and AD DC will use the same network but might be different sub-network

Before deploying CAM integrated with an existing DC, please make sure the following requirements have been satisfied:      
### 1.  Create an account with delegated permissions to join a computer to domain.   
* the account should have minimum permissions to:
* Create Computer Objects
* Delete Computer Objects
* Read All Properties
* Write All Properties
* Read Permissions
* Modify Permissions
* Change Password
* Reset Password
* Validated write to DNS host name
* Validated write to service principle name

Both command line tool **dsacls.exe** and **"Active Directory Users and Computers" MMC snap-in** GUI can be used.
the following links are as examples:  
https://jonconwayuk.wordpress.com/2011/10/20/minimum-permissions-required-for-account-to-join-workstations-to-the-domain-during-deployment/   
https://www.youtube.com/watch?v=qht0xeQ9xuc  
https://www.youtube.com/watch?v=v8t6eAd17RM  
https://seneej.com/2012/10/25/grant-a-helpdesksupport-user-rights-to-join-computers-to-domain/  

If the service account performing the domain join does not have adequate permissions you may  see 'Access is denied' errors as described on the following page:

https://support.microsoft.com/en-us/help/932455/error-message-when-non-administrator-users-who-have-been-delegated-con  

sample code to delegate a domain account to join a computer to domain using powershell and utility tool dsacls.exe:

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


### 2. Create a domain group and delegate Service Account to add member to the group. 

samle code to create domain group using powershell and utility tool dsacls.exe
    
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


### 3. Enable Service Account to perform remote powershell commands on the domain controller machine. 
The following steps need to be performed for Windows Server 2012 R2 or higher:

* The service account should be added to the **"Remote Management Users"** group.
The following powershell commands should be run on the domain controller(s) to enable remote powershell and allow remote powershell connections from a remote computer not located in the same network as the domain controller:
* Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null
* Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any | Out-Null

For Server 2008 R2 the following powershell command needs to be run on the domain contoller(s)
* Enable-PSRemoting -Force

sample code to add a domain account to the **"Remote Management Users"** group:

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


### 4. Enable LDAPS on the domain controller. 
There are two methods of enabling LDAPS on a DC.
* Method #1: install an Enterprise Root CA  
  The first method is the easiest: LDAPS is automatically enabled when you install an Enterprise Root CA on a Domain Controller. If you install the AD-CS role and specify the type of setup as "Enterprise" on a DC, all DCs in the forest will be automatically be configured to accept LDAPS. 

* Method #2: add a Digital Certificate on DC  
  Requirements for an LDAPS certificate:    
       1) Digital Certificate must be valid for the purpose of "Server Authentication." This means that they must contain the Server Authentication object identifier (OID). OIDs are like the Internet domain name space. They are series of numbers separated by dots, each with a specific meaning. For this purpose, the relevant OID we're looking for is 1.3.6.1.5.5.7.3.1. 
       2) The Subject name or the first name in the Subject Alternative Name (SAN) must match the Fully Qualified Domain Name (FQDN) of the host machine, such as Subject:CN=server.domain.com.  
       3) The host machine account needs to have access to the private key. This is done when the digital certificate request is issued from that machine, or when the private key was exported and imported to a different machine.  
    
The following links provide exmples for setting up LDAPS:  
https://support.microsoft.com/en-us/help/321051/how-to-enable-ldap-over-ssl-with-a-third-party-certification-authority  
http://pdhewaju.com.np/2017/03/02/configuring-secure-ldap-connection-server-2016/  
https://www.petri.com/enable-secure-ldap-windows-server-2008-2012-dc  

