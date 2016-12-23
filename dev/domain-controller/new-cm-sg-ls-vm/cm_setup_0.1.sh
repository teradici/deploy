#!/bin/bash
#
# There must be three arguments passed to this script.
# first argument is the FQDN of the broker.
# second argument is the activation code for the license server

#get the install zip files
wget https://teradeploy.blob.core.windows.net/binaries/P-CM-1.6_SG-1.12.zip -P /tmp/
wget https://teradeploy.blob.core.windows.net/binaries/P-LS-1.0.3.zip -P /tmp/


unzip -o /tmp/P-CM-1.6_SG-1.12.zip

#remove unwanted jdk's
yum -y remove java-1.6.0-openjdk
yum -y remove java-1.7.0-openjdk

#open required ports
iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 4172 -j ACCEPT
#iptables -I INPUT 1 -p tcp --dport 8090 -j ACCEPT   # for LM Web GUI
iptables -I INPUT 1 -p tcp --dport 27000 -j ACCEPT  # for LM licensing Port
iptables -I INPUT 1 -p tcp --dport 27001 -j ACCEPT  # for LM vendor daemon Port
iptables -I INPUT 1 -p udp --dport 4172 -j ACCEPT
service iptables save


#get current networking configuration and use that for system setup. If there are dynamic IP's in the system THIS WILL EVENTUALLY FAIL.
mypublicip=`dig +short myip.opendns.com @resolver1.opendns.com`
#alternates if opendns turns off: curl ipinfo.io/ip    curl ipecho.net/plain ; echo
myhostname=`hostname`
myprivateip=`ifconfig eth0 | awk '/inet addr/ {gsub("addr:", "", $2); print $2}'`

echo "Detected hostname= $myhostname privateIP = $myprivateip publicip = $mypublicip"

#add local IP and name to hosts file.
echo " $myprivateip   $myhostname" >> /etc/hosts
service network restart

sh cm_setup.sh

# modify CM setup
#make the 'original' file one time only
cp -n /etc/ConnectionManager.conf /etc/ConnectionManager.conf.orig
awk -v broker=$1 '/^PcoipAddress/{printf "PcoipAddress = %s\n",broker;next};{print}' /etc/ConnectionManager.conf.orig | \
awk  -v lserver="27000@$myprivateip" '/^LicenseServerAddress/{printf "LicenseServerAddress = %s\n",lserver;next};{print}'  \
    > ConnectionManager.conf
cp -f ConnectionManager.conf /etc/ConnectionManager.conf

echo "Finished setting up CM without SG"


# external IP is set, setup SG
if [ -n "$mypublicip" ]; then

	#first, enable sg in CM config and copy it back again
	awk '/^SecurityGatewayEnabled/{printf "SecurityGatewayEnabled = true\n";next};{print}'  /etc/ConnectionManager.conf >  ConnectionManager.conf
	cp -f ConnectionManager.conf /etc/ConnectionManager.conf

	#make the 'original' file one time only
	cp -n /etc/SecurityGateway.conf /etc/SecurityGateway.conf.orig
	awk -v externalip=$4 '/^ExternalRoutableIP/{printf "ExternalRoutableIP = %s\n",externalip;next};{print}' /etc/SecurityGateway.conf.orig > SecurityGateway.conf
	cp -f SecurityGateway.conf /etc/SecurityGateway.conf

	echo "Finished setting up SG"
fi


# now setup license server
#
#sudo rm -rf /opt/FNPLicenseServerManager
unzip -o /tmp/P-LS-1.0.3.zip
yum -y install redhat-lsb.i686
mkdir license-server_1.0.3
mv license-server_1.0.3.tar.gz license-server_1.0.3/
cd license-server_1.0.3/
tar xvf license-server_1.0.3.tar.gz
awk '{ sub(/-i console/,"-i silent"); print }' install.sh > install-silent.sh
sh install-silent.sh > lm_install.log

# setup vendor daemon port#
# copy original config file to temp location
cp -f /opt/FNPLicenseServerManager/conf/server.xml /opt/FNPLicenseServerManager/conf/server_orig.xml
#rewrite original with new port#
awk '{ sub(/name="TERADICI" port="0"/,"name=\"TERADICI\" port=\"27001\""); print }' /opt/FNPLicenseServerManager/conf/server_orig.xml > /opt/FNPLicenseServerManager/conf/server.xml

#activate licenses
cd /opt/FNPLicenseServerManager/utils
./pcoip-activate-license.sh -k "$2" -c 1

#to return license
# need to find license, use  ./pcoip-view-license.sh and look for the line with "Fulfillment ID:" in it
# then:
#./pcoip-return-license.sh -f fulfillment_ID

# reboot now
# shutdown -r +1 "Server will restart in 1 minute."

exit 0

# /opt/FNPLicenseServerManager/conf/server.xml
#    <vendorDaemons>
#      <daemon dateBasedVersion="false" dlog="false" executable="TERADICI/TERADICI" license="licenses/TERADICI/Teradici_license_dummy.lic" logFile="logs/TERADICI.log" logOverwrite="false" name="TERADICI" port="27001" restartRetries="10"/>
#    </vendorDaemons>


