In order to deploy CAM that is integrated with customer own Active Directory (AD), the folloing requirements must be met. When deploying CAM, the **account credential and DC fqdn** must be provided, and the DC must be able to communicated with the given **fqdn**.

# 1) Creating an account with delegated permissions to join a computer to domain. 

The following steps setup an account with delegated privileges to join a computer to domain, assuming an account already created, otherwise, please create an account first.

 * Login Domain Controller Server.
 * Lanuch Active Directory Users and Computers.
 * Locate the **OU** that you want to join a computer to and right-click and then click Delegate Control. 
 * The **Delegation of Control Wizard** opens, click **Next**
 * In the **Users or Groups** page, click **Add** to add a specific user or a specific group to the **Selected users and groups** list, and then click **Next**
 * In the **Tasks to Delegate** page, click **Create a custom task to delegate**, and then click **Next**.
 * In the **Active Directory Object Type** page, Click **Only the following objects in the folder**, and then from the list, click to select the **Computer objects** check box. Then, select the check boxes below the list, **Create selected objects in this folder** and **Delete selected objects in this folder**, Click **Next**.
 * In the **Permissions** page, click to select the following permission check boxes from list:  
       &nbsp;&nbsp;&nbsp;&nbsp;**Reset Password**  
       &nbsp;&nbsp;&nbsp;&nbsp;**Read and write Account Restrictions**  
       &nbsp;&nbsp;&nbsp;&nbsp;**Validated write to DNS host name**  
       &nbsp;&nbsp;&nbsp;&nbsp;**Validated write to service principal name**
 * Click **Next** to **the Completing the Delegation of Control Wizard** page, after review then click **Finish**.


# 2) Enable remote powershell admin on a Domain Controller (DC) machine. 

The following steps enable remote powershell admin

* Login Domain Controller Server.
* Start Windows PowerShell as an administrator.
* Check the configuration of WinRM service by running following command:  
  **Get-WmiObject Win32_Service | Where-Object { $_.Name -eq 'WinRM'} | Format-Table**  
  The value of the StartMode property in the output should be "Auto" and the value of the Status property in the output should be "Running"
* Set the StartMode property of WinRM service to Automatic by running following command if needed:  
  **Set-Service WinRM -StartupType Automatic**  
  **Restart-Service -Name WinRM**
* run command to enable remote powershell: **Enable-PSRemoting -Force**


# 3) Enable LDAPs on a on Domain Controller (DC) machine. 
    
Basically, there are two methods of enabling LDAPS on a DC.

* Method #1: install an Enterprise Root CA  
  The first method is the easiest: LDAPS is automatically enabled when you install an Enterprise Root CA on a Domain Controller. If you install the AD-CS role and specify the type of setup as ¡°Enterprise¡± on a DC, all DCs in the forest will be automatically be configured to accept LDAPS.  
    
  
* Method #2: add a Digital Certificate on DC  
  Requirements for an LDAPS certificate:  
  1) Digital Certificate must be valid for the purpose of ¡°Server Authentication.¡± This means that they must contain the Server Authentication object identifier (OID). OIDs are like the Internet domain name space. They are series of numbers separated by dots, each with a specific meaning. For this purpose, the relevant OID we¡¯re looking for is 1.3.6.1.5.5.7.3.1.  
  2) The Subject name or the first name in the Subject Alternative Name (SAN) must match the Fully Qualified Domain Name (FQDN) of the host machine, such as Subject:CN=server.domain.com.  
  3) The host machine account needs to have access to the private key. This is done when the digital certificate request is issued from that machine, or when the private key was exported and imported to a different machine.  
    
  The following steps setup LDAPS:  
  1)  Create the request file.
  2)  Submit the request to a CA. 
  3)  Retrieve the certificate that is issued, and then save the certificate as Certnew.cer in the same folder as the request file.       Open the file in Notepad, paste the encoded certificate into the file, and then save the file.  
      Note The saved certificate must be encoded as base64. 
  4)  Install the issued certificate. 
  5)  Verify that the certificate is installed in the computer's Personal store. To do this, follow these steps:  
      Start Microsoft Management Console (MMC).  
      Add the Certificates snap-in that manages certificates on the local computer.  
      Expand Certificates (Local Computer), expand Personal, and then expand Certificates.  
      A new certificate should exist in the Personal store. In the Certificate Properties dialog box, the intended purpose displayed       is Server Authentication. This certificate is issued to the computer's fully qualified host name.
  6)  Enable the host machine account to access to the private key.  
      The private key will be present in the following location C:\ProgramData\Microsoft\Crypto\Keys\<UniqueContainerName>  
      Right Click the private key path and click properties --> Security and add read permissions for **NETWORK SERVICE**.
  
  Verifying an LDAPS connection:
  1)  Start the Active Directory Administration Tool (Ldp.exe).
  2)  On the Connection menu, click Connect.
  3)  Type the name of the domain controller to which you want to connect.
      Type 636 as the port number.
  4)  Click OK.  