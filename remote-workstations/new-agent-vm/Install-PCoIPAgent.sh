#!/bin/bash
# Copyright (c) 2018 Teradici Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

if [[ $# -le 2 ]]
then
    AGENT_TYPE="$1"
    if [[ $# -eq 2 ]]
    then
        BINARY_LOCATION="$2"
    fi
else
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
    # the thirteenth argument is whether or not to enable auto-shutdown
    # (Remove whitespace and force to lowercase)
    ENABLE_AUTO_SHUTDOWN="$(echo -e "${13}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    # the fourteenth argument is the idle timer in minutes for auto-shutdown
    AUTO_SHUTDOWN_IDLE_TIMER="${14}"
    # the fifteenth argument is the Binaries location
    BINARY_LOCATION="${15}"
fi

update_kernel_dkms()
{
    echo "-->Updating" | tee -a "$INST_LOG_FILE"
    sudo yum -y update
    local exitCode=$?
    if [[ $exitCode -eq 0 ]]
        then
        echo "-->Installing kernel-devel" | tee -a "$INST_LOG_FILE"
        sudo yum -y install kernel-devel
        exitCode=$?
        if [[ $exitCode -eq 0 ]]
        then
            echo "-->Adding EPEL-7 Repository" | tee -a "$INST_LOG_FILE"
            sudo rpm -Uvh --quiet https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
            echo "-->Installing DKMS" | tee -a "$INST_LOG_FILE"
            sudo yum -y install dkms
            exitCode=$?
            if [[ $exitCode -ne 0 ]]
            then
                echo "Failed installing DKMS" | tee -a "$INST_LOG_FILE"
            fi
        else
            echo "Failed installing kernel-devel" | tee -a "$INST_LOG_FILE"
        fi
    else
        echo "Failed update" | tee -a "$INST_LOG_FILE"
    fi

    return $exitCode
}

# need to reboot after install
disable_nouveau()
{
    echo "-->Blacklisting nouveau drivers" | tee -a "$INST_LOG_FILE"
    echo 'blacklist nouveau' | sudo tee -a /etc/modprobe.d/nouveau.conf
    echo 'blacklist lbm-nouveau' | sudo tee -a /etc/modprobe.d/nouveau.conf
}

# need to reboot after install Linux Integration Services for Hyper-V
install_lis()
{
    local LIS_FILE="lis-rpms-4.2.4-1.tar.gz"
    echo "-->Downloading Linux Integration Service for Hyper-V (Version: ${LIS_FILE})" | tee -a "$INST_LOG_FILE"

    wget --retry-connrefused --tries=3 --waitretry=5  "https://download.microsoft.com/download/6/8/F/68FE11B8-FAA4-4F8D-8C7D-74DA7F2CFC8C/$LIS_FILE"
    local exitCode=$?

    if [[ $exitCode -eq 0 ]]
    then
        echo "-->Installing Linux Integration Services for Hyper-V " | tee -a "$INST_LOG_FILE"
        tar xvzf "$LIS_FILE"

        cd LISISO
        sudo ./install.sh
        exitCode=$?

        if [[ $exitCode -ne 0 ]]
        then
            echo "-->Failed to install Linux Integration Services for Hyper-V " | tee -a "$INST_LOG_FILE"            
        fi

        cd ..
    else
        echo "Download Failed" | tee -a "$INST_LOG_FILE"
    fi

    return $exitCode
}

install_nvidia_driver()
{
    local exitCode=0

    if [[ -z $BINARY_LOCATION ]]
    then
        exitCode=1
        echo "Binary Location not specified" | tee -a "$INST_LOG_FILE"
    else
        local FILE_NAME="NVIDIA-Linux-x86_64-384.111-grid.run"
        echo "-->Downloading nVidia Driver ${FILE_NAME} from ${BINARY_LOCATION}" | tee -a "$INST_LOG_FILE"

        wget --retry-connrefused --tries=3 --waitretry=5  "${BINARY_LOCATION}/${FILE_NAME}"
        exitCode=$?

        if [[ $exitCode -eq 0 ]]
        then
            echo "-->Installing nVidia Driver" | tee -a "$INST_LOG_FILE"
            chmod +x "$FILE_NAME"

            sudo "./$FILE_NAME" -Z -X -s
            exitCode=$?

            if [[ $exitCode -eq 0 ]]
            then
                echo "-->Install Success" | tee -a "$INST_LOG_FILE"
                sudo cp /etc/nvidia/gridd.conf.template /etc/nvidia/gridd.conf

                echo 'IgnoreSP=TRUE' | sudo tee -a /etc/nvidia/gridd.conf
            else
                echo "Install Failed" | tee -a "$INST_LOG_FILE"
            fi
        else
            echo "Download Failed" | tee -a "$INST_LOG_FILE"
        fi
    fi

    return $exitCode
}

join_domain()
{
    # Join domain
    echo "-->Install required packages to join domain" | tee -a "$INST_LOG_FILE"
    sudo yum -y install sssd realmd oddjob oddjob-mkhomedir adcli samba-common samba-common-tools krb5-workstation openldap-clients policycoreutils-python

    echo "-->restarting messagebus service" | tee -a "$INST_LOG_FILE"
    sudo systemctl restart messagebus    
    local exitCode=$?
    if [[ $exitCode -ne 0 ]]
    then
        echo "Failed to restart messagebus service" | tee -a "$INST_LOG_FILE"
        return 106
    fi

    echo "-->enable and start sssd service" | tee -a "$INST_LOG_FILE"
    sudo systemctl enable sssd --now    
    exitCode=$?
    if [[ $exitCode -ne 0 ]]
    then
        echo "Failed to start sssd service" | tee -a "$INST_LOG_FILE"
        return 106
    fi

    echo "-->Joining the domain" | tee -a "$INST_LOG_FILE"
    if [[ -n "${OU}" ]]
    then
        echo "$PASSWORD" | sudo realm join --user="$USERNAME" --computer-ou="${OU}" "$DOMAIN_NAME" >&2
    else
        echo "$PASSWORD" | sudo realm join --user="$USERNAME" "$DOMAIN_NAME" >&2
    fi
    exitCode=$?
    if [[ $exitCode -eq 0 ]]
    then
        echo "-->Joined Domain '${DOMAIN_NAME}' and OU '${OU}'" | tee -a "$INST_LOG_FILE"
    else
        echo "Failed to join Domain '${DOMAIN_NAME}' and OU '${OU}'" | tee -a "$INST_LOG_FILE"
        return 106
    fi

    echo "-->Configuring settings" | tee -a "$INST_LOG_FILE"
    sudo sed -i '$ a\dyndns_update = True\ndyndns_ttl = 3600\ndyndns_refresh_interval = 43200\ndyndns_update_ptr = True\nldap_user_principal = nosuchattribute' /etc/sssd/sssd.conf
    sudo sed -c -i "s/\\(use_fully_qualified_names *= *\\).*/\\1False/" /etc/sssd/sssd.conf
    sudo sed -c -i "s/\\(fallback_homedir *= *\\).*/\\1\\/home\\/%u/" /etc/sssd/sssd.conf
    sudo domainname "$VM_NAME.$DOMAIN_NAME"
    echo "%$DOMAIN_NAME\\\\Domain\\ Admins ALL=(ALL) ALL" > /etc/sudoers.d/sudoers

    echo "-->Registering with DNS" | tee -a "$INST_LOG_FILE"
    DOMAIN_UPPER=$(echo "$DOMAIN_NAME" | tr '[:lower:]' '[:upper:]')
    IP_ADDRESS=$(hostname -I | grep -Eo '10.([0-9]*\.){2}[0-9]*')
    echo "$PASSWORD" | sudo kinit "$USERNAME"@"$DOMAIN_UPPER"
    touch dns_record
    echo "update add $VM_NAME.$DOMAIN_NAME 600 a $IP_ADDRESS" > dns_record
    echo "send" >> dns_record
    sudo nsupdate -g dns_record

    echo "-->Join the group" | tee -a "$INST_LOG_FILE"
    # set the domain controller address
    DC_ADDRESS=$(host -t srv _ldap._tcp."$DOMAIN_NAME" | awk '{print $NF}')
    sudo yum -y install python-ldap
    echo "-->Creating and executing a python script to join the group" | tee -a "$INST_LOG_FILE"
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
import sys
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
        try:
            group_dn = self.get_group_info(group_name)[0]
            if not group_dn:
                print >> sys.stderr, "The domain group '{}' does not exist.".format(group_name)
                return False
            computer_dn = self.get_computer_info(computer_to_add)[0]
            member = [((ldap.MOD_ADD, 'member', [computer_dn]))]
            self.admin_ldap.modify_s(group_dn, member)
        except ldap.CONSTRAINT_VIOLATION, err:
            print >> sys.stderr, err
            return False
        except ldap.LDAPError, err:
            print >> sys.stderr, err
            return False
        finally:
            self.admin_ldap.unbind_s()

        return True

parser = argparse.ArgumentParser(description='Join a computer to a group')
parser.add_argument("-d", "--domain", dest="domain", required=True, help="Domain name")
parser.add_argument("-a", "--address", dest="address", required=True, help="domain controller address")
parser.add_argument("-u", "--user_name", dest="user_name", required=True, help="user name to login to domain controller")
parser.add_argument("-p", "--password", dest="password", required=True, help="password to login to domain controller")
parser.add_argument("-c", "--computer", dest="computer", required=True, help="computer to add to the group")
parser.add_argument("-g", "--group", dest="group", help="group name")
args = parser.parse_args()

try:
    active_d = ldap_lib(args.address, args.user_name, args.password, args.domain)    
    active_d.add_computer_to_group(args.computer, args.group)
except Exception, err:
    print >> sys.stderr, err
EOF

    local msg=$( sudo python $file_path -d "$DOMAIN_NAME" -a "$DC_ADDRESS" -u "$USERNAME" -p "$PASSWORD" -c "$VM_NAME" -g "$GROUP"  2>&1 >/dev/null ) 

    if [[ ! -z "$msg" ]]
    then 
        echo "Failed to add machine '$VM_NAME' to domain group '$GROUP'." | sudo tee -a /var/log/domainGroupJoinFile.log  | tee -a "$INST_LOG_FILE"
        echo "$msg" | sudo tee -a /var/log/domainGroupJoinFile.log  | tee -a "$INST_LOG_FILE"
    else
        echo "-->Added machine '$VM_NAME' to domain group '$GROUP'." | tee -a "$INST_LOG_FILE"
    fi
}

install_gui()
{
    sudo yum -y update  # --exclude=WALinuxAgent

    # Install Desktop
    echo "-->Install desktop" | tee -a "$INST_LOG_FILE"
    sudo yum -y groupinstall "Server with GUI"
    local exitCode=$?
    if [[ $exitCode -ne 0 ]]
    then
        echo "Failed to install desktop" | tee -a "$INST_LOG_FILE"
        return $exitCode
    fi

    # install firefox
    echo "-->Install firefox" | tee -a "$INST_LOG_FILE"
    sudo yum -y install firefox

    # The below command will change runlevel from runlevel 3 to runelevel 5
    sudo systemctl set-default graphical.target

    sudo systemctl start graphical.target
}

install_pcoip_agent()
{
    # Install the Teradici package key
    echo "-->Install the Teradici package key" | tee -a "$INST_LOG_FILE"
    sudo rpm --import https://downloads.teradici.com/rhel/teradici.pub.gpg

    # Add the Teradici repository
    echo "-->Add the Teradici repository" | tee -a "$INST_LOG_FILE"

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

    sudo wget --retry-connrefused --tries=3 --waitretry=5 -O /etc/yum.repos.d/pcoip.repo "$agent_repo_url"

    local exitCode=$?
    if [[ $exitCode -ne 0 ]]
    then
        echo "Failed to add teradici repository." | tee -a "$INST_LOG_FILE"
        # let's define exit code 100 for this case
        return 100
    fi

    # Install the EPEL repository
    #echo "-->Install the EPEL repository" | tee -a "$INST_LOG_FILE"
    sudo rpm -Uvh --quiet https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

    # Install the PCoIP Agent
    local dispName=("first" "second" "third")
    for idx in {1..3}
    do
        echo "-->Install the PCoIP $AGENT_TYPE agent at ${dispName[idx -1]} time" | tee -a "$INST_LOG_FILE"
        sudo yum -y install "pcoip-agent-$AGENT_TYPE"
        exitCode=$?

        if [[ $exitCode -eq 0 ]]
        then
            # to check service pcoip-agent is allowed by firewall
            sudo firewall-cmd --list-services | grep "pcoip-agent"
            exitCode=$?
            if [[ $exitCode -ne 0 ]]
            then
                start_firewall

                echo "enable service pcoip-agent in firewall." | tee -a "$INST_LOG_FILE"
                sudo firewall-cmd --reload > /dev/null
                sudo firewall-cmd --permanent --add-service=pcoip-agent > /dev/null
                sudo firewall-cmd --reload > /dev/null                

                # to check service pcoip-agent is allowed by firewall after enabling
                sudo firewall-cmd --list-services | grep "pcoip-agent"
                exitCode=$?
                if [[ $exitCode -ne 0 ]]
                then
                    echo "could not enable service pcoip-agent in firewall." | tee -a "$INST_LOG_FILE"
                fi
            fi
        fi

        if [[ $exitCode -eq 0 ]]
        then
            break
        else
            #delay 5 seconds
            echo "Failed to install pcoip agent at ${dispName[idx -1]} time." | tee -a "$INST_LOG_FILE"
            sleep 5
            sudo yum -y remove "pcoip-agent-$AGENT_TYPE"
            if [[ $idx -eq 3 ]]
            then
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
    echo "-->Register license code" | tee -a "$INST_LOG_FILE"
    for idx in {1..5}
    do
        pcoip-register-host --registration-code="$REGISTRATION_CODE"
        pcoip-validate-license
        local exitCode=$?

        if [[ $exitCode -eq 0 ]]
        then
            break
        else
            if [[ $idx -eq 5 ]]
            then
                echo "Failed to register pcoip agent license."
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
    echo "-->Install SumoLogic collector" | tee -a "$INST_LOG_FILE"
    mkdir /tmp/sumo
    wget "https://collectors.sumologic.com/rest/download/linux/64" -O /tmp/sumo/SumoCollector.sh && sudo chmod +x /tmp/sumo/SumoCollector.sh
    wget "$STORAGEURI/user.properties$SAS_TOKEN" -O /tmp/sumo/user.properties
    wget "$STORAGEURI/sumo-agent-vm-linux.json$SAS_TOKEN" -O /tmp/sumo/sumo-agent-vm-linux.json
    JSON_FILE=/tmp/sumo/sumo-agent-vm-linux.json
    echo "-->Attempting to set sumo collector ID" | tee -a "$INST_LOG_FILE"
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
    echo "-->Install idle shutdown" | tee -a "$INST_LOG_FILE"
    mkdir /tmp/idleShutdown
    wget "$STORAGEURI/Install-Idle-Shutdown.sh$SAS_TOKEN" -O /tmp/idleShutdown/Install-Idle-Shutdown-raw.sh
    awk '{ sub("\r$", ""); print }' /tmp/idleShutdown/Install-Idle-Shutdown-raw.sh > /tmp/idleShutdown/Install-Idle-Shutdown.sh && sudo chmod +x /tmp/idleShutdown/Install-Idle-Shutdown.sh
    INSTALL_OPTS="--idle-timer ${AUTO_SHUTDOWN_IDLE_TIMER}"
    if [[ "${ENABLE_AUTO_SHUTDOWN}" = "false" ]]; then
        INSTALL_OPTS="${INSTALL_OPTS} --disabled"
    fi
    sudo /tmp/idleShutdown/Install-Idle-Shutdown.sh "${INSTALL_OPTS}"
}

exit_restart()
{
    echo "-->Rebooting" | tee -a "$INST_LOG_FILE"
    (sleep 1; sudo reboot) &
    exit
}

start_firewall() 
{
    if [[ "$(firewall-cmd --state)" != "running" ]] 
    then  
        echo "enable and start firewall." | tee -a "$INST_LOG_FILE"
        systemctl enable firewalld --now 
        sleep 2
    fi
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

if [[ "$AGENT_TYPE" != "$AGENT_TYPE_STANDARD" ]] && [[ "$AGENT_TYPE" != "$AGENT_TYPE_GRAPHICS"  ]]
then
    echo "Unknown agent type $AGENT_TYPE." | tee -a "$INST_LOG_FILE"
    # let's define exit code 105 for this case
    exit 105
fi

if [[ -f "$INST_LOG_FILE" ]]
then
    INST_LAST_STEP=$(grep "^step*" "${INST_LOG_FILE}" | tail -1) 
fi

if [[ "$INST_LAST_STEP" == "initial" ]]
then
    echo "start installing pcoip $AGENT_TYPE agent" | tee -a "$INST_LOG_FILE"

    echo "step1 starting" | tee -a "$INST_LOG_FILE"

    sudo yum -y install wget

    install_SumoLogic

    join_domain

    EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 0 ]]
    then
        install_gui
        EXIT_CODE=$?
        if [[ $EXIT_CODE -eq 0 ]]
        then
            INST_LAST_STEP="step1 done"
        else
            INST_LAST_STEP="step1 failure: $EXIT_CODE"
        fi
    else
        INST_LAST_STEP="step1 failure: $EXIT_CODE"
    fi

    echo "$INST_LAST_STEP" | tee -a "$INST_LOG_FILE"
fi

if [[ "$INST_LAST_STEP" == "step1 done" ]]
then 
    echo "step2 starting" | tee -a "$INST_LOG_FILE"

    install_pcoip_agent

    EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 0 ]]
    then
        INST_LAST_STEP="step2 done"
    else
        INST_LAST_STEP="step2 failure: $EXIT_CODE"
    fi

    echo "$INST_LAST_STEP" | tee -a "$INST_LOG_FILE"
fi

if [[ "$INST_LAST_STEP" == "step2 done" ]]
then
    echo "step3 starting" | tee -a "$INST_LOG_FILE"

    register_pcoip_license

    EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 0 ]]
    then
        install_idle

        INST_LAST_STEP="step3 done"
    else
        INST_LAST_STEP="step3 failure: $EXIT_CODE"
    fi

    echo "$INST_LAST_STEP" | tee -a "$INST_LOG_FILE"
fi

if [[ "$AGENT_TYPE" == "$AGENT_TYPE_GRAPHICS" ]]
then
    if [[ "$INST_LAST_STEP" == "step3 done" ]]
    then
        echo "start installing nvidia driver" | tee -a "$INST_LOG_FILE"

        echo "step4 starting" | tee -a "$INST_LOG_FILE"
        if [[ -z $BINARY_LOCATION ]]
        then
            EXIT_CODE=1
            INST_LAST_STEP="step4 failure: Binary Location not specified"
            echo $INST_LAST_STEP | tee -a "$INST_LOG_FILE"
        else
            update_kernel_dkms
            EXIT_CODE=$?            
        fi
        
        if [[ $EXIT_CODE -eq 0 ]]
        then
            disable_nouveau

            INST_LAST_STEP="step4 done"

            echo "$INST_LAST_STEP" | tee -a "$INST_LOG_FILE"

            #schedule job to continue installation
            script_file=$(realpath "$0")
            chmod +x "$script_file"

            # only need to pass 1 parameter $AGENT_TYPE to continue
            (sudo crontab -l 2>/dev/null; echo "@reboot bash $script_file ${AGENT_TYPE} ${BINARY_LOCATION}") | sudo crontab -

            #exit and restart VM
            exit_restart
        else
            INST_LAST_STEP="step4 failure: $EXIT_CODE"
            echo $INST_LAST_STEP | tee -a "$INST_LOG_FILE"
        fi        
    fi

    if [[ "$INST_LAST_STEP" == "step4 done" ]]
    then
        echo "step5 starting" | tee -a "$INST_LOG_FILE"

        install_lis

        EXIT_CODE=$?

        if [[ $EXIT_CODE -eq 0 ]]
        then
            INST_LAST_STEP="step5 done"
        else
            INST_LAST_STEP="step5 failure: $EXIT_CODE"
        fi

        echo "$INST_LAST_STEP" | tee -a "$INST_LOG_FILE"

        if [[ $EXIT_CODE -eq 0 ]]
        then
            exit_restart
        fi
    fi

    if [[ "$INST_LAST_STEP" == "step5 done" ]]
    then
        echo "step6 starting" | tee -a "$INST_LOG_FILE"

        install_nvidia_driver
        EXIT_CODE=$?

        if [[ $EXIT_CODE -eq 0 ]]
        then
            INST_LAST_STEP="step6 done"
        else
            INST_LAST_STEP="step6 failure: $EXIT_CODE"
        fi

        echo "$INST_LAST_STEP" | tee -a "$INST_LOG_FILE"
    fi

    #remove job
    sudo crontab -r
fi

if [[ $EXIT_CODE -eq 0 ]]
then
    (sleep 1; sudo reboot) &
fi

exit $EXIT_CODE
