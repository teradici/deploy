#!/bin/bash
#
# There must be three arguments passed to this script.
# first argument is the FQDN of the broker.
# second argument is the activation code for the license server

#get the install zip files
wget https://teradeploy.blob.core.windows.net/binaries/P-CM-1.6_SG-1.12.zip -P /tmp/
#wget https://teradeploy.blob.core.windows.net/binaries/P-LS_1.1.0.zip -P /tmp/


unzip -o /tmp/P-CM-1.6_SG-1.12.zip

#remove unwanted jdk's
yum -y remove java-1.6.0-openjdk
yum -y remove java-1.7.0-openjdk

#open required ports
iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 8080 -j ACCEPT
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

service security_gateway stop
service connection_manager stop

# modify CM setup
#make the 'original' file
cp -n /etc/ConnectionManager.conf /etc/ConnectionManager.conf.orig
#awk -v broker=$1 '/^PcoipAddress/{printf "PcoipAddress = %s\n",broker;next};{print}' /etc/ConnectionManager.conf.orig | \
#awk  -v lserver="27000@$myprivateip" '/^LicenseServerAddress/{printf "LicenseServerAddress = %s\n",lserver;next};{print}'  \
#    > ConnectionManager.conf

awk -v broker=$1 '/^PcoipAddress/{printf "PcoipAddress = %s\n",broker;next};{print}' /etc/ConnectionManager.conf.orig > ConnectionManager.conf


cp -f ConnectionManager.conf /etc/ConnectionManager.conf


echo "Setting up Tomcat to allow an unencrypted link over port 8080"

#make the 'original' file
cp -n /opt/Teradici/thirdparty/tomcat/conf/server.xml /opt/Teradici/thirdparty/tomcat/conf/server.xml.orig

#add port 8080 http listener and make the 'info' page available at 'root' to not confuse L7 load balancers.
awk  '/<Service name=\"Catalina\">/{printf "<Service name=\"Catalina\">\n<Connector port=\"8080\" protocol=\"HTTP/1.1\" connectionTimeout=\"20000\" redirectPort=\"443\" />\n";next};{print}' \
 /opt/Teradici/thirdparty/tomcat/conf/server.xml.orig | \
awk '/xmlValidation=\"false\" xmlNamespaceAware=\"false\"/{print $0; print "<Context path=\"\" docBase=\"/opt/Teradici/thirdparty/tomcat/webapps/info\" />\n";next}1' \
 > /opt/Teradici/thirdparty/tomcat/conf/server.xml

echo "Finished setting up CM without SG"


# external IP is set, setup SG
if [ -n "$mypublicip" ]; then

	#first, enable sg in CM config and copy it back again
	awk '/^SecurityGatewayEnabled/{printf "SecurityGatewayEnabled = true\n";next};{print}'  /etc/ConnectionManager.conf >  ConnectionManager.conf
	cp -f ConnectionManager.conf /etc/ConnectionManager.conf

	#make the 'original' file one time only
	cp -n /etc/SecurityGateway.conf /etc/SecurityGateway.conf.orig
	awk -v externalip=$mypublicip '/^ExternalRoutableIP/{printf "ExternalRoutableIP = %s\n",externalip;next};{print}' /etc/SecurityGateway.conf.orig > SecurityGateway.conf
	cp -f SecurityGateway.conf /etc/SecurityGateway.conf

	echo "Finished setting up SG"
fi


# now setup license server
#
#sudo rm -rf /opt/FNPLicenseServerManager
#unzip -o /tmp/P-LS_1.1.0.zip
#yum -y install redhat-lsb.i686
#mkdir license-server_1.1
#mv license-server_1.1.0.tar.gz license-server_1.1/
#cd license-server_1.1/
#tar xvf license-server_1.1.0.tar.gz
#awk '{ sub(/-i console/,"-i silent\nsleep 120\nchmod +x /opt/FNPLicenseServerManager/lmadmin"); print }' install.sh > install-silent.sh
#sh install-silent.sh > lm_install.log

#service lmadmin stop

# setup vendor daemon port#
# copy original config file to temp location
#cp -f /opt/FNPLicenseServerManager/conf/server.xml /opt/FNPLicenseServerManager/conf/server_orig.xml
#rewrite original with new port#
#awk '{ sub(/name="TERADICI" port="0"/,"name=\"TERADICI\" port=\"27001\""); print }' /opt/FNPLicenseServerManager/conf/server_orig.xml > /opt/FNPLicenseServerManager/conf/server.xml

#activate licenses
#cd /opt/FNPLicenseServerManager/utils
#./pcoip-activate-license.sh -k "$2" -c 1

#to return license
# need to find license, use  ./pcoip-view-license.sh and look for the line with "Fulfillment ID:" in it
# then:
#./pcoip-return-license.sh -f fulfillment_ID

# reboot now
# shutdown -r +1 "Server will restart in 1 minute."

#or just restart all the services
service security_gateway restart
service connection_manager restart
#service lmadmin restart

#Hack... try to restart the CM after 60 seconds to ensure that the info record is remapped to ROOT. This does not seem to be happening on its own.

sleep 60
service connection_manager restart


exit 0

# /opt/FNPLicenseServerManager/conf/server.xml
#    <vendorDaemons>
#      <daemon dateBasedVersion="false" dlog="false" executable="TERADICI/TERADICI" license="licenses/TERADICI/Teradici_license_dummy.lic" logFile="logs/TERADICI.log" logOverwrite="false" name="TERADICI" port="27001" restartRetries="10"/>
#    </vendorDaemons>


