#!/bin/bash

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
# the eighth argument is the agent installer channel
AGENT_CHANNEL="$8"
# the ninth argument is the userStorageAccountUri
STORAGEURI="$9"
# the tenth argument is the sumo collector ID
COLLECTOR_ID="${10}"
# the eleventh argument is the SaS Storage account token
SAS_TOKEN="${11}"
# the twelfth argument is the Computer OU string
OU="${12}"

update_kernel_dkms() 
{
  sudo yum -y update

  sudo yum -y install kernel-devel

  sudo rpm -Uvh --quiet https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

  sudo yum -y install dkms
}

# need to reboot after install
disable_nouveal()
{
    echo 'blacklist nouveau' | sudo tee -a /etc/modprobe.d/nouveau.conf
    
    echo 'blacklist lbm-nouveau' | sudo tee -a /etc/modprobe.d/nouveau.conf
}

# need to reboot after install Linux Integration Services for Hyper-V
install_lis()
{    
    local LIS_FILE="lis-rpms-4.2.3-4.tar.gz"
    
    wget --retry-connrefused --tries=3 --waitretry=5  http://download.microsoft.com/download/6/8/F/68FE11B8-FAA4-4F8D-8C7D-74DA7F2CFC8C/$LIS_FILE

    tar xvzf $LIS_FILE

    cd LISISO
    
    sudo ./install.sh
    
    local exitCode=$?

    cd ..
    
    return $exitCode
}

install_nvidia_driver()
{
    local FILE_NAME="NVIDIA-Linux-x86_64-384.73-grid.run"
    
    wget --retry-connrefused --tries=3 --waitretry=5  https://teradeploy.blob.core.windows.net/binaries/$FILE_NAME  

    chmod +x $FILE_NAME

    sudo ./$FILE_NAME -Z -X -s

    local exitCode=$?

    if [ $exitCode -eq 0 ] 
    then
        sudo cp /etc/nvidia/gridd.conf.template /etc/nvidia/gridd.conf
        
        echo 'IgnoreSP=TRUE' | sudo tee -a /etc/nvidia/gridd.conf
    fi
    
    return $exitCode
}

join_domain()
{
    # Join domain
    echo "-->Install required packages to join domain"
    sudo yum -y install sssd realmd oddjob oddjob-mkhomedir adcli samba-common samba-common-tools krb5-workstation openldap-clients policycoreutils-python
    sudo systemctl enable sssd

    echo "-->Joining the domain"
    if [ -n "${OU}" ]
    then
        echo "$PASSWORD" | sudo realm join --user="$USERNAME" --computer-ou="${OU}" "$DOMAIN_NAME" >&2
    else
        echo "$PASSWORD" | sudo realm join --user="$USERNAME" "$DOMAIN_NAME" >&2
    fi
    if [ $? -eq 0 ]
    then
        echo "Joined Domain ${DOMAIN_NAME} and OU ${OU}"
    else
        echo "Failed to join Domain ${DOMAIN_NAME} and OU ${OU}"
        return 106
    fi

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
}

install_gui() 
{
    # Make sure Linux OS is up to date
    echo "--> Updating Linux OS to latest"

    # Exclude WALinuxAgent due to it failing to update from within an Azure Custom Script
    sudo yum -y update --exclude=WALinuxAgent

    # Install Desktop
    echo "-->Install desktop"	
    #sudo yum -y groupinstall 'X Window System' 'GNOME'
    sudo yum -y groupinstall "Server with GUI"
    
    # sudo yum groups mark convert

    # install firefox
    echo "-->Install firefox"
    sudo yum -y install firefox
    
    #echo "-->set default graphical target"
    # The below command will change runlevel from runlevel 3 to runelevel 5 
    # sudo systemctl set-default graphical.target
    
    #echo "-->start graphical target"
    # sudo systemctl start graphical.target	
}	

install_pcoip_agent()
{
    # Install the Teradici package key
    echo "-->Install the Teradici package key"
    sudo rpm --import https://downloads.teradici.com/rhel/teradici.pub.gpg
    
    # Add the Teradici repository
    echo "-->Add the Teradici repository"
    
    agent_repo_url="https://downloads.teradici.com/rhel/pcoip.repo"
    case "$AGENT_CHANNEL" in 
        "beta")
            agent_repo_url="https://downloads.teradici.com/rhel/pcoip-beta.repo"
            ;;
        "dev")
            agent_repo_url="https://downloads.teradici.com/rhel/pcoip-dev.repo"
            ;;   
        *)
            agent_repo_url="https://downloads.teradici.com/rhel/pcoip.repo"
            ;;       
    esac
    
    sudo wget --retry-connrefused --tries=3 --waitretry=5 -O /etc/yum.repos.d/pcoip.repo $agent_repo_url
    
    local exitCode=$?
    if [ $exitCode -ne 0 ]
    then
        echo "failed to add teradici repository."
        # let's define exit code 100 for this case
        return 100
    fi
    
    # Install the EPEL repository	
    #echo "-->Install the EPEL repository"
    sudo rpm -Uvh --quiet https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

    sudo yum -y update --exclude=WALinuxAgent
        
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
                return 101
            fi
            #delay 5 seconds        
            sleep 5
        fi
    done
        
    return 0
}

register_pcoip_license() 
{
    # register license code
    echo "-->Register license code"
    for idx in {1..5}
    do
        pcoip-register-host --registration-code="$REGISTRATION_CODE"
        pcoip-validate-license    
        local exitCode=$?
        
        if [ $exitCode -eq 0 ]
        then
            break
        else
            if [ $idx -eq 5 ]
            then
                echo "failed to register pcoip agent license."
                # let's define exit code 102 for this case
                return 102
            fi
            sleep 10
        fi
    done		
    
    return 0
}

install_SumoLogic() 
{
    # Install and setup the Sumo Collector
    echo "-->Install SumoLogic collector"
    mkdir /tmp/sumo
    wget "https://collectors.sumologic.com/rest/download/linux/64" -O /tmp/sumo/SumoCollector.sh && sudo chmod +x /tmp/sumo/SumoCollector.sh
    wget "$STORAGEURI/user.properties$SAS_TOKEN" -O /tmp/sumo/user.properties
    wget "$STORAGEURI/sumo-agent-vm-linux.json$SAS_TOKEN" -O /tmp/sumo/sumo-agent-vm-linux.json
    JSON_FILE=/tmp/sumo/sumo-agent-vm-linux.json
    echo "Attemtping to set sumo collector ID to: " "$COLLECTOR_ID"
    sed -i s/collectorID/"$COLLECTOR_ID"/ /tmp/sumo/user.properties
    sed -i 's|syncsourceFile|'$JSON_FILE'|' /tmp/sumo/user.properties

    sudo /tmp/sumo/SumoCollector.sh -q -varfile user.properties

    # service collector install - configures the collector to start at boot time
    service collector install
    service collector restart
    service collector status
}

install_idle()
{
    # Install idle shutdown script
    echo "-->Install idle shutdown"
    mkdir /tmp/idleShutdown
    wget "$STORAGEURI/Install-Idle-Shutdown.sh$SAS_TOKEN" -O /tmp/idleShutdown/Install-Idle-Shutdown-raw.sh 
    awk '{ sub("\r$", ""); print }' /tmp/idleShutdown/Install-Idle-Shutdown-raw.sh > /tmp/idleShutdown/Install-Idle-Shutdown.sh && sudo chmod +x /tmp/idleShutdown/Install-Idle-Shutdown.sh
    sudo /tmp/idleShutdown/Install-Idle-Shutdown.sh -install
}

exit_restart()
{
    (sleep 1; sudo reboot) &
    exit;	
}

# run start from here

AGENT_TYPE_STANDARD="standard"
AGENT_TYPE_GRAPHICS="graphics"

#define global EXIT_CODE variable
EXIT_CODE=1
INST_LOG_FILE=/root/install_pcoip_agent.status
INST_LAST_STEP="initial"

AGENT_CHANNEL=$(tr '[:upper:]' '[:lower:]' <<<"$AGENT_CHANNEL")
AGENT_TYPE=$(tr '[:upper:]' '[:lower:]' <<<"$AGENT_TYPE")

if [ "$AGENT_TYPE" != "$AGENT_TYPE_STANDARD" ] && [ "$AGENT_TYPE" != "$AGENT_TYPE_GRAPHICS"  ]
then
    echo "unknown agent type $AGENT_TYPE."
    # let's define exit code 105 for this case
    exit 105
fi

if [ -f $INST_LOG_FILE ]
then
    INST_LAST_STEP=$(tail -1 $INST_LOG_FILE) 
fi

if [ "$INST_LAST_STEP" == "initial" ]
then
    echo "start installing pcoip $AGENT_TYPE agent" | tee $INST_LOG_FILE

    echo "step1 starting" | tee -a $INST_LOG_FILE

    sudo yum install wget

    install_SumoLogic

    install_gui

    join_domain

    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]
    then
        INST_LAST_STEP="step1 done"
    else
        INST_LAST_STEP="step1 failure: $EXIT_CODE"
    fi

    echo "$INST_LAST_STEP" | tee -a $INST_LOG_FILE
fi	

if [ "$INST_LAST_STEP" == "step1 done" ]
then 
    echo "step2 starting" | tee -a $INST_LOG_FILE

    install_pcoip_agent
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]
    then
        INST_LAST_STEP="step2 done"
    else
        INST_LAST_STEP="step2 failure: $EXIT_CODE"
    fi
    
    echo "$INST_LAST_STEP" | tee -a $INST_LOG_FILE
fi

if [ "$INST_LAST_STEP" == "step2 done" ]
then 
    echo "step3 starting" | tee -a $INST_LOG_FILE

    register_pcoip_license
    
    EXIT_CODE=$?
    
    install_idle

    if [ $EXIT_CODE -eq 0 ]
    then 
        INST_LAST_STEP="step3 done"			
    else
        INST_LAST_STEP="step3 failure: $EXIT_CODE"
    fi

    echo "$INST_LAST_STEP" | tee -a $INST_LOG_FILE
fi

if [ $AGENT_TYPE == $AGENT_TYPE_GRAPHICS ]
then
    echo "start installing nvidia driver" | tee -a $INST_LOG_FILE

    if [ "$INST_LAST_STEP" == "step3 done" ]
    then
        echo "step4 starting" | tee -a $INST_LOG_FILE
        update_kernel_dkms
    
        disable_nouveal
    
        INST_LAST_STEP="step4 done"
    
        echo "$INST_LAST_STEP" | tee -a $INST_LOG_FILE

        #schedule job to continue installation	
        script_file=$(realpath "$0")
        chmod +x $script_file

        params=""
        for var in "$@"
        do
            params="$params \"$var\""
        done

        (sudo crontab -l 2>/dev/null; echo "@reboot bash $script_file  $params") | sudo crontab -
    
        #exit and restart VM
        exit_restart
    fi	
    
    if [ "$INST_LAST_STEP" == "step4 done" ]
    then
        echo "step5 starting" | tee -a $INST_LOG_FILE

        install_lis
    
        EXIT_CODE=$?
    
        if [ $EXIT_CODE -eq 0 ]
        then 
            INST_LAST_STEP="step5 done"
        else
            INST_LAST_STEP="step5 failure: $EXIT_CODE"
        fi

        echo "$INST_LAST_STEP" | tee -a $INST_LOG_FILE
    
        if [ $EXIT_CODE -eq 0 ]
        then	
            exit_restart
        fi
    fi

    if [ "$INST_LAST_STEP" == "step5 done" ]
    then
        echo "step6 starting" | tee -a $INST_LOG_FILE

        install_nvidia_driver
        EXIT_CODE=$?
    
        if [ $EXIT_CODE -eq 0 ]
        then 
            INST_LAST_STEP="step6 done"
        else
            INST_LAST_STEP="step6 failure: $EXIT_CODE"
        fi

        echo "$INST_LAST_STEP" | tee -a $INST_LOG_FILE
    fi
fi

#remove job
sudo crontab -r

if [ $EXIT_CODE -eq 0 ]
then	
    (sleep 1; sudo reboot) &
fi

exit $EXIT_CODE;