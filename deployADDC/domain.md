Deploy CAM with existing Active Directory Domain Controller
==========================================================

In order to deploy CAM integrated with customer own AD DC, the following parameters has to be provided:  
* **domain name** the domain name that the VM will join
* **domain group name** the name of domain group that VM will join
* **account credential** which has permissions to join computer to domain, domain group and has permission to use remote powershell  in the joined domain domain controller 
* **NetWork Id** which the CAM workstations will reside
* **Sub Network for VM**
* **Sub Network for Gateway** this is specaill for application gateway and must not be used for other purpose.
* **Two IP addresses** the two IP addresses which are used by connect manager and should be within the address space of Sub Network for VM
> **Notes** It assumes CAM and AD DC will use the same network but might be different sub-network

Before deploymenting CAM integrated with existing AD DC, please prepare the following requirements:      
### 1.  Creating an account with delegated permissions to join a computer to domain.   
* the account should has minimum permissions:
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
https://support.microsoft.com/en-us/help/932455/error-message-when-non-administrator-users-who-have-been-delegated-con  
https://www.youtube.com/watch?v=qht0xeQ9xuc  
https://www.youtube.com/watch?v=v8t6eAd17RM  
https://seneej.com/2012/10/25/grant-a-helpdesksupport-user-rights-to-join-computers-to-domain/  
https://jonconwayuk.wordpress.com/2011/10/20/minimum-permissions-required-for-account-to-join-workstations-to-the-domain-during-deployment/   

### 2. Enable remote powershell over https on ADDC machine. 
To enabling PowerShell remoting over https, you should deploy a SSL certificate to remote server.
you can refer the follow link as examples:  
https://github.com/AppVeyor/AppRolla/wiki/Configuring-Windows-PowerShell-remoting

### 3. Enable Service Account to use remote powershell on ADDC machine. 
Add Service Account to become a member of the group **"Remote Management Users"**

### 4. Enable LDAPs on AD DC. 
Basically, there are two methods of enabling LDAPS on a DC.
* Method #1: install an Enterprise Root CA  
  The first method is the easiest: LDAPS is automatically enabled when you install an Enterprise Root CA on a Domain Controller. If you install the AD-CS role and specify the type of setup as "Enterprise" on a DC, all DCs in the forest will be automatically be configured to accept LDAPS. 

* Method #2: add a Digital Certificate on DC  
  Requirements for an LDAPS certificate:    
       1) Digital Certificate must be valid for the purpose of "Server Authentication." This means that they must contain the Server Authentication object identifier (OID). OIDs are like the Internet domain name space. They are series of numbers separated by dots, each with a specific meaning. For this purpose, the relevant OID we're looking for is 1.3.6.1.5.5.7.3.1. 
       2) The Subject name or the first name in the Subject Alternative Name (SAN) must match the Fully Qualified Domain Name (FQDN) of the host machine, such as Subject:CN=server.domain.com.  
      3) The host machine account needs to have access to the private key. This is done when the digital certificate request is issued from that machine, or when the private key was exported and imported to a different machine.  
    
The following links as exmples to setup LDAPS:  
https://support.microsoft.com/en-us/help/321051/how-to-enable-ldap-over-ssl-with-a-third-party-certification-authority  
http://pdhewaju.com.np/2017/03/02/configuring-secure-ldap-connection-server-2016/  
https://www.petri.com/enable-secure-ldap-windows-server-2008-2012-dc  
