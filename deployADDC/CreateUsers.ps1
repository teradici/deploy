# Modifed from https://github.com/RobBridgeman/ADImporter

# Credit for original script to Helge Klein https://helgeklein.com.
# Adapted to allow higher numbers of users with the same information set.

# Summary of changes.
# Reduced Male and Female names into one list for ease of expansion
# Changed Displayname code to create each combination of names possible
# Changed sAMAccountname generation to add unique account ID with orgShortName as suffix.


# Known issues
# Usercount (For me anyway) seems to be inaccurate when import completes. May be related to errorcheck compensation when usercount is reduced. Consistently seem to get many more users that intended.

param(
    [Int32]     $userCount,
    [string]    $dnsDomain,
    [string]    $baseUrl="https://raw.githubusercontent.com/teradici/deploy/TSW-67106-use-external-ad/deployADDC",
    [String]    $groupName="My CAM Test Group"
)

Set-StrictMode -Version 2

Import-Module ActiveDirectory

# Download list of names and and addresses and phone and area codes
if (! $baseUrl.EndsWith('/')) {
    $baseUrl = $baseUrl + '/'
}
$addressLocation = "${baseUrl}Addresses.txt"
$firstnameLocation = "${baseUrl}Firstnames.txt"
$lastnameLocation = "${baseUrl}Lastnames.txt"
$postalAreaLocation = "${baseUrl}PostalAreaCode.txt"

Invoke-WebRequest -UseBasicParsing -Uri $addressLocation -OutFile Addresses.txt
Invoke-WebRequest -UseBasicParsing -Uri $firstnameLocation -OutFile Firstnames.txt
Invoke-WebRequest -UseBasicParsing -Uri $lastnameLocation -OutFile Lastnames.txt
Invoke-WebRequest -UseBasicParsing -Uri $postalAreaLocation -OutFile PostalAreaCode.txt


# Global variables
#
# User properties

# This is used to build a user's sAMAccountName
$orgShortName = ($dnsDomain -split "\.")[0]
# Initial password set for the user
$initialPassword = "Password1!"
# Used for the user object's company attribute
$company = "$orgShortName co"
# Departments and associated job titles to assign to the users
$departments = (
    @{"Name" = "Finance & Accounting"; Positions = ("Manager", "Accountant", "Data Entry")},
    @{"Name" = "Human Resources"; Positions = ("Manager", "Administrator", "Officer", "Coordinator")},
    @{"Name" = "Sales"; Positions = ("Manager", "Representative", "Consultant")},
    @{"Name" = "Marketing"; Positions = ("Manager", "Coordinator", "Assistant", "Specialist")},
    @{"Name" = "Engineering"; Positions = ("Manager", "Engineer", "Scientist")},
    @{"Name" = "Consulting"; Positions = ("Manager", "Consultant")},
    @{"Name" = "IT"; Positions = ("Manager", "Engineer", "Technician")},
    @{"Name" = "Planning"; Positions = ("Manager", "Engineer")},
    @{"Name" = "Contracts"; Positions = ("Manager", "Coordinator", "Clerk")},
    @{"Name" = "Purchasing"; Positions = ("Manager", "Coordinator", "Clerk", "Purchaser")}
)
# Country codes for the countries used in the address file
$phoneCountryCodes = @{"GB" = "+44"}

# Other parameters
# How many users to create
$locationCount = 1                          # How many different offices locations to use

# Files used
$firstNameFile = "Firstnames.txt"            # Format: FirstName
$lastNameFile = "Lastnames.txt"              # Format: LastName
$addressFile = "Addresses.txt"               # Format: City,Street,State,PostalCode,Country
$postalAreaFile = "PostalAreaCode.txt"       # Format: PostalCode,PhoneAreaCode

#
# Read input files
#
$firstNames = Import-CSV $firstNameFile
$lastNames = Import-CSV $lastNameFile
$addresses = Import-CSV $addressFile
$postalAreaCodesTemp = Import-CSV $postalAreaFile

# Convert the postal & phone area code object list into a hash
$postalAreaCodes = @{}
foreach ($row in $postalAreaCodesTemp)
{
    $postalAreaCodes[$row.PostalCode] = $row.PhoneAreaCode
}
$postalAreaCodesTemp = $null

#
# Preparation
#
$securePassword = ConvertTo-SecureString -AsPlainText $initialPassword -Force

# Select the configured number of locations from the address list
$locations = @()
$addressIndexesUsed = @()
for ($i = 0; $i -le $locationCount; $i++)
{
    # Determine a random address
    $addressIndex = -1
    do
    {
        $addressIndex = Get-Random -Minimum 0 -Maximum $addresses.Count
    } while ($addressIndexesUsed -contains $addressIndex)
    
    # Store the address in a location variable
    $street = $addresses[$addressIndex].Street
    $city = $addresses[$addressIndex].City
    $state = $addresses[$addressIndex].State
    $postalCode = $addresses[$addressIndex].PostalCode
    $country = $addresses[$addressIndex].Country
    $locations += @{"Street" = $street; "City" = $city; "State" = $state; "PostalCode" = $postalCode; "Country" = $country}
    
    # Do not use this address again
    $addressIndexesUsed += $addressIndex
}

#
# Create the users
#

#
# Randomly determine this user's properties
#
   
# Sex & name
$i = 0
$employeeNumber = 0
$userObjs = New-Object System.Collections.ArrayList

if ($i -lt $userCount) 
{
    while( $true ) 
    {
        $Fname = $firstNames[$(Get-Random -Minimum 0 -Maximum $firstNames.Count)].Firstname
        $Lname = $lastNames[$(Get-Random -Minimum 0 -Maximum $lastNames.Count)].Lastname

        $displayName = $Fname + " " + $Lname

        # Address
        $locationIndex = Get-Random -Minimum 0 -Maximum $locations.Count
        $street = $locations[$locationIndex].Street
        $city = $locations[$locationIndex].City
        $state = $locations[$locationIndex].State
        $postalCode = $locations[$locationIndex].PostalCode
        $country = $locations[$locationIndex].Country
   
        # Department & title
        $departmentIndex = Get-Random -Minimum 0 -Maximum $departments.Count
        $department = $departments[$departmentIndex].Name
        $title = $departments[$departmentIndex].Positions[$(Get-Random -Minimum 0 -Maximum $departments[$departmentIndex].Positions.Count)]

        # Phone number
        if (-not $phoneCountryCodes.ContainsKey($country))
        {
            "ERROR: No country code found for $country"
            continue
        }
        if (-not $postalAreaCodes.ContainsKey($postalCode))
        {
            "ERROR: No country code found for $country"
            continue
        }
        $officePhone = $phoneCountryCodes[$country] + "-" + $postalAreaCodes[$postalCode].Substring(1) + "-" + (Get-Random -Minimum 100000 -Maximum 1000000)
   
        # Build the sAMAccountName: $orgShortName + employee number
        $sAMAccountName = $orgShortName + $employeeNumber
        # Check if User alreay exists
        $userExists = $false
        Try { 
            $userExists = Get-ADUser -LDAPFilter "(sAMAccountName=$sAMAccountName)" 
        } Catch {
        }
        if ($userExists)
        {
            $i=$i-1
            if ($i -lt 0)
            {$i=0}
            continue
        }

        #
        # Create the user account
        #
        $userObj = New-ADUser -SamAccountName $sAMAccountName -Name "$displayName" -AccountPassword $securePassword -Enabled $true -GivenName $Fname -Surname $Lname -DisplayName "$displayName" -EmailAddress "$Fname.$Lname@$dnsDomain" -StreetAddress "$street" -City "$city" -PostalCode $postalCode -State $state -Country $country -UserPrincipalName "$sAMAccountName@$dnsDomain" -Company $company -Department $department -EmployeeNumber $employeeNumber -Title $title -OfficePhone $officePhone -PassThru
        $userObjs.Add($userObj) > $null

        "Created user #" + ($i+1) + ", $displayName, $sAMAccountName, $title, $department, $street, $city"
        $i = $i+1
        $employeeNumber = $employeeNumber+1

        if ($i -ge $userCount) 
        {
            "Loop Complete. Exiting"
            break
        }
    }
}

# create group
Write-Host "================ preparing domain group ========================="
$name = "My Test Root User"
$rootOuObj = Get-ADOrganizationalUnit -Filter " Name -eq `"${name}`" "
if ($rootOuObj -eq $null) {
    Write-Host "creating OU ${name}"
    $rootOuObj = New-ADOrganizationalUnit  -Name $name -ProtectedFromAccidentalDeletion $False -PassThru
}

$groupObj = Get-ADGroup -Filter " Name -eq `"${groupName}`" "
if ($groupObj -eq $null) {
    Write-Host "creating group ${groupName}"
    $groupObj = New-ADGroup -Name $groupName -GroupCategory Security -GroupScope Global -Path $rootOuObj.DistinguishedName -Description "Members of this group are for CAM" -PassThru
} else {
    $members=Get-ADGroupMember -Identity $groupObj.ObjectGUID
    if ($members) {
        Remove-ADGroupMember -Identity $groupObj.ObjectGUID -Members $members -Confirm:$false
    }
}

$name = "Test Level 1 OU"
$level1OuObj = Get-ADOrganizationalUnit -Filter " Name -eq `"${name}`" "
if ($level1OuObj -eq  $null) {
    Write-Host "creating OU ${name}"
    $level1OuObj = New-ADOrganizationalUnit  -Name $name -Path $rootOuObj.DistinguishedName -ProtectedFromAccidentalDeletion $False -PassThru
}

$groupBName = $groupName + 'B'
$groupBObj = Get-ADGroup -Filter " Name -eq `"${groupBName}`" "
if ($groupBObj -eq $null) {
    Write-Host "creating group ${groupName}"
    $groupBObj = New-ADGroup -Name $groupBName -GroupCategory Security -GroupScope Global -Path $level1OuObj.DistinguishedName -Description "Members of this group are for CAM" -PassThru
} else {
    $members=Get-ADGroupMember -Identity $groupBObj.ObjectGUID
    if ($members) {
        Remove-ADGroupMember -Identity $groupBObj.ObjectGUID -Members $members -Confirm:$false
    }
}
Add-ADGroupMember -Identity $groupObj.ObjectGUID -Members $groupBObj

$groupMemberNumber = if ($userObjs.Count -lt 20) {$userObjs.Count} else {20}
Write-Host "================ adding $groupMemberNumber users to domain group ======================"
for ($i=0; $i -lt $groupMemberNumber; $i++) {
    $userObj = $userObjs[$i]

    if (($i % 5) -eq 0) {
        Disable-ADAccount $userObj
    }

    if (($i % 2) -eq 0) {
        Add-ADGroupMember -Identity $groupObj.ObjectGUID -Members $userObj
    } else {
        Add-ADGroupMember -Identity $groupBObj.ObjectGUID -Members $userObj
    }
}
exit