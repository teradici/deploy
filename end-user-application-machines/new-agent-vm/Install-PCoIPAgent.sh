#!/bin/bash

install_driver()
{
    # Install kernel-source/kernel-devel and gcc
    sudo yum -y install kernel-source kernel-devel gcc
    FILE_NAME="NVIDIA-Linux-x86_64-367.106-grid.run"
    FILE_LOCATION="/root/$FILE_NAME"
    # Download Driver first
    echo "Downloading and Installing Nvidia driver"
    sudo wget --retry-connrefused --tries=3 --waitretry=5 -O $FILE_LOCATION https://binarystore.blob.core.windows.net/thirdparty/nvidia/$FILE_NAME
    exitCode=$?
    if [ $exitCode -ne 0 ]
    then
        echo "failed to download Nvidia driver."
        # let's define exit code 103 for this case
        exit 103
    fi
    # Change file permission
    sudo chmod 744 $FILE_LOCATION
    # run installer
    sudo $FILE_LOCATION -Z -X -s
    exitCode=$?
    
    if [ $exitCode -eq 0 ]
    then
        echo "Driver is installed successfully"
    else
        echo "failed to install Nvidia driver. Will create a script to install driver when machine boots up"
        file_path="/root/install_driver.sh"
        cat <<EOF >$file_path
#!/bin/bash
if [ -e /root/.first_boot ]
then
    if [ -e /root/.second_boot ]
    then
        exit 0
    else
        touch /root/.second_boot
        sudo $FILE_LOCATION -Z -X -s        
    fi
else
    touch /root/.first_boot
    sudo $FILE_LOCATION -Z -X -s
    (sleep 2;  sudo shutdown -f -r +0)&
fi
EOF
        sudo chmod 744 $file_path
        (crontab -l 2>/dev/null; echo "@reboot $file_path") | crontab -
        # let's define exit code 104 for this case
        #exit 104
    fi
}

# the first argument is the Registration Code of PCoIP agent
REGISTRATION_CODE="$1"
# the second argument is the agent type
AGENT_TYPE="$2"
# the third argument is the VM name
VM_NAME="$3"
# the forth argument is the domain name
DOMAIN_NAME="$4"
# the fifith argument is the username
USERNAME="$5"
# the sixth argument is the password
PASSWORD="$6"
# the seventh argument is the domain group to join
GROUP="$7"

# Make sure Linux OS is up to date
echo "--> Updating Linux OS to latest"
# Exclude WALinuxAgent due to it failing to update from within an Azure Custom Script
sudo yum -y update --exclude=WALinuxAgent

# If it's graphic agent, install Nvidia Driver
case "$AGENT_TYPE" in 
    "Graphics")
        install_driver
        AGENT_TYPE='graphics'
        ;;
    "Standard")
        AGENT_TYPE='standard'
        ;;   
    *)
        echo "unknown agent type $AGENT_TYPE."
        # let's define exit code 105 for this case
        exit 105
        ;;       
esac

# Join domain
echo "-->Install required packages to join domain"
sudo yum -y install sssd realmd oddjob oddjob-mkhomedir adcli samba-common samba-common-tools krb5-workstation openldap-clients policycoreutils-python
sudo systemctl enable sssd

echo "-->Joining the domain"
echo "$PASSWORD" | sudo realm join --user="$USERNAME" "$DOMAIN_NAME"

echo "-->Configuring settings"
sudo sed -i '$ a\dyndns_update = True\ndyndns_ttl = 3600\ndyndns_refresh_interval = 43200\ndyndns_update_ptr = True\nldap_user_principal = nosuchattribute' /etc/sssd/sssd.conf
sudo sed -c -i "s/\\(use_fully_qualified_names *= *\\).*/\\1False/" /etc/sssd/sssd.conf
sudo sed -c -i "s/\\(fallback_homedir *= *\\).*/\\1\\/home\\/%u/" /etc/sssd/sssd.conf
sudo domainname "$VM_NAME.$DOMAIN_NAME"
echo "%$DOMAIN_NAME\\\\Domain\\ Admins ALL=(ALL) ALL" > /etc/sudoers.d/sudoers

echo "-->Registering with DNS"
DOMAIN_UPPER=$(echo "$DOMAIN_NAME" | tr '[:lower:]' '[:upper:]')
IP_ADDRESS=$(hostname -I | grep -Eo '10.([0-9]*\.){2}[0-9]*')
echo "$PASSWORD" | sudo kinit "$USERNAME"@"$DOMAIN_UPPER"
touch dns_record
echo "update add $VM_NAME.$DOMAIN_NAME 600 a $IP_ADDRESS" > dns_record
echo "send" >> dns_record
sudo nsupdate -g dns_record

echo "-->Join the group"
# set the domain controller address
DC_ADDRESS=$(host -t srv _ldap._tcp."$DOMAIN_NAME" | awk '{print $NF}')
sudo yum -y install python-ldap
echo "Creating a python script to join the group"
file_path=/root/join_group.py
cat <<EOF >$file_path
'''
'''
'''
/**
* Copyright Teradici Corporation 2012-2014. All Rights Reserved.
*
* No portions of this material may be reproduced in any form without the
* written permission of Teradici Corporation.
*
* All information contained in this document is Teradici Corporation company
* private, proprietary, and trade secret.
*
*/
'''
import platform
import ldap
import ldap.filter
import ldap.modlist
import ldap.sasl
import argparse

class ldap_lib(object):
    def __init__(self, server_address, username, password, domain):
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        self.ldap_server = 'ldap://%s' % server_address
        self.master_user = username
        self.master_password = password
        self.domain = '@%s' % domain
        self.base = 'DC=' + domain
        self.base = self.base.replace('.', ',DC=')

        try:
            self.admin_ldap = ldap.initialize(self.ldap_server)
            self.admin_ldap.start_tls_s()
            self.admin_ldap.simple_bind_s(self.master_user + self.domain, self.master_password)
        except ldap.LDAPError, err:
            raise err

    def get_computer_info(self, computer_name):
        """
        Get computer information
        """
        user_base = "%s" % (self.base)
        user_filter = "(&(sAMAccountName=%s$)(objectClass=computer))" \
                        % ldap.filter.escape_filter_chars(computer_name, 0)
        user_scope = ldap.SCOPE_SUBTREE
        try:
            results = self.admin_ldap.search_s(user_base, user_scope, user_filter)
        except ldap.LDAPError, err:
            raise err
        if results:
            return results[0]
        return

    def get_group_info(self, group_name):
        """
        Get group information
        """
        user_base = "%s" % (self.base)
        user_filter = "(&(objectClass=GROUP)(cn=%s))" \
                        % ldap.filter.escape_filter_chars(group_name, 0)
        user_scope = ldap.SCOPE_SUBTREE
        try:
            results = self.admin_ldap.search_s(user_base, user_scope, user_filter)
        except ldap.LDAPError, err:
            raise err
        if results:
            return results[0]
        return

    def add_computer_to_group(self, computer_to_add, group_name):
        """
        Add computer to a specific group
        """
        group_dn = self.get_group_info(group_name)[0]
        computer_dn = self.get_computer_info(computer_to_add)[0]
        member = [((ldap.MOD_ADD, 'member', [computer_dn]))]
        try:
            self.admin_ldap.modify_s(group_dn, member)
        except ldap.CONSTRAINT_VIOLATION, err:
            print err
            return False
        except ldap.LDAPError, err:
            print err
            return False
        return True

parser = argparse.ArgumentParser(description='Join a computer to a group')
parser.add_argument("-d", "--domain", dest="domain", required=True, help="Domain name")
parser.add_argument("-a", "--address", dest="address", required=True, help="domain controller address")
parser.add_argument("-u", "--user_name", dest="user_name", required=True, help="user name to login to domain controller")
parser.add_argument("-p", "--password", dest="password", required=True, help="password to login to domain controller")
parser.add_argument("-c", "--computer", dest="computer", required=True, help="computer to add to the group")
parser.add_argument("-g", "--group", dest="group", help="group name")
args = parser.parse_args()

active_d = ldap_lib(args.address, args.user_name, args.password, args.domain)
active_d.add_computer_to_group(args.computer, args.group)

EOF
sudo python $file_path -d "$DOMAIN_NAME" -a "$DC_ADDRESS" -u "$USERNAME" -p "$PASSWORD" -c "$VM_NAME" -g "$GROUP"


# Install the EPEL repository
echo "-->Install the EPEL repository"
sudo rpm -Uvh --quiet https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Install the Teradici package key
echo "-->Install the Teradici package key"
sudo rpm --import https://downloads.teradici.com/rhel/teradici.pub.gpg

# Add the Teradici repository
echo "-->Add the Teradici repository"
sudo wget --retry-connrefused --tries=3 --waitretry=5 -O /etc/yum.repos.d/pcoip.repo https://downloads.teradici.com/rhel/pcoip.repo
exitCode=$?
if [ $exitCode -ne 0 ]
then
    echo "failed to add teradici repository."
    # let's define exit code 100 for this case
    exit 100
fi

# Install the PCoIP Agent
echo "-->Install the PCoIP $AGENT_TYPE agent"
for idx in {1..3}
do
    sudo yum -y install pcoip-agent-$AGENT_TYPE
    exitCode=$?
    
    if [ $exitCode -eq 0 ]
    then
        break
    else
        #delay 5 seconds
        sleep 5
        sudo yum -y remove pcoip-agent-$AGENT_TYPE
        if [ $idx -eq 3 ]
        then
            echo "failed to install pcoip agent."
            # let's define exit code 101 for this case
            exit 101
        fi
        #delay 5 seconds        
        sleep 5
    fi
done
    

# register license code
echo "-->Register license code"
for idx in {1..3}
do
    pcoip-register-host --registration-code="$REGISTRATION_CODE"
    pcoip-validate-license    
    exitCode=$?
    
    if [ $exitCode -eq 0 ]
    then
        break
    else
        if [ $idx -eq 3 ]
        then
            echo "failed to register pcoip agent license."
            # let's define exit code 102 for this case
            exit 102
        fi
        sleep 5
    fi
done

# Install Desktop
echo "-->Install desktop"
# sudo yum -y groupinstall "Server with GUI"
sudo yum -y groupinstall 'X Window System' 'GNOME'

# install firefox
echo "-->Install firefox"
sudo yum -y install firefox

echo "-->set default graphical target"
# The below command will change runlevel from runlevel 3 to runelevel 5 
sudo systemctl set-default graphical.target

echo "-->start graphical target"
sudo systemctl start graphical.target

(sleep 2;  sudo shutdown -f -r +0)&
exit 0