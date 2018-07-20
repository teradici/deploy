#!/bin/bash
#
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
# There must be one argument passed to this script.
# first argument is the FQDN of the broker.

# Update system to latest
yum -y update --exclude=WALinuxAgent

# Install and setup the Sumo Collector
mkdir /tmp/sumo
wget "https://collectors.sumologic.com/rest/download/linux/64" -O /tmp/sumo/SumoCollector.sh && sudo chmod +x /tmp/sumo/SumoCollector.sh
wget "$3/user.properties" -O /tmp/sumo/user.properties
wget "$3/sumo_cm_vm.json" -O /tmp/sumo/sumo_cm_vm.json
JSON_FILE=/tmp/sumo/sumo_cm_vm.json
echo "Attempting to set sumo collector ID to: " "$2"
sed -i s/collectorID/"$2"/ /tmp/sumo/user.properties
sed -i 's|syncsourceFile|'$JSON_FILE'|' /tmp/sumo/user.properties

sudo /tmp/sumo/SumoCollector.sh -q -varfile user.properties

# service collector install - configures the collector to start at boot time
service collector install
service collector restart
service collector status


# get the install zip files
CM_SG_FILENAME='CM_SG.zip'
wget https://teradeploy.blob.core.windows.net/binaries/$CM_SG_FILENAME -P /tmp/
unzip -o /tmp/$CM_SG_FILENAME

# remove unwanted jdk's
yum -y remove java-1.6.0-openjdk
yum -y remove java-1.7.0-openjdk

# open required ports
iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 8080 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 4172 -j ACCEPT
iptables -I INPUT 1 -p udp --dport 4172 -j ACCEPT
service iptables save

# 4th parameter is if the SG should be enabled. If not present, assume true. Using the value after the '='
if [ -n "${4}" ]; then
	SGENABLED="${4#*=}"
	if [ "${SGENABLED^^}" = "TRUE" ]; then sge=true; else sge=false; fi
else
	sge=true
fi


# get current networking configuration and use that for system setup. If there are dynamic IP's in the system THIS WILL EVENTUALLY FAIL.
# alternates if opendns turns off: curl ipinfo.io/ip    curl ipecho.net/plain ; echo
if [ ${sge} = "true" ]; then
	echo "Enabling PCoIP security gateway"
	mypublicip=$(dig +short myip.opendns.com @resolver1.opendns.com)
else
	echo "Not enabling PCoIP security gateway"
	mypublicip="Did not search."
fi

myhostname=$(hostname)
myprivateip=$(ifconfig eth0 | awk '/inet / {gsub("addr:", "", $2); print $2}')

echo "Detected hostname= $myhostname privateIP = $myprivateip publicIP = $mypublicip"

# add local IP and name to hosts file.
echo " $myprivateip   $myhostname" >> /etc/hosts
service network restart

# find folder name
FOLDER_NAME=$(find . -type f -name 'cm_setup.sh' | sed -r 's|/[^/]+$||') 

# if folder name contain space, change to cm_sg
case "$FOLDER_NAME" in  
     *\ * )
           mv "$FOLDER_NAME" cm_sg
		   FOLDER_NAME=cm_sg
          ;;
       *)
           echo "no space in directory name"
           ;;
esac

sh "$FOLDER_NAME"/cm_setup.sh

service security_gateway stop
service connection_manager stop

# modify CM setup
#
# make the 'original' file
cp -n /etc/ConnectionManager.conf /etc/ConnectionManager.conf.orig
awk -v broker="$1" '/^PcoipAddress/{printf "PcoipAddress = %s\n",broker;next};{print}' /etc/ConnectionManager.conf.orig > ConnectionManager.conf
sed --in-place --expression="s|\(LogLevel\s*=\).*|\1 TRACE|g" ConnectionManager.conf

cp -f ConnectionManager.conf /etc/ConnectionManager.conf

echo "Setting up Tomcat to allow an unencrypted link over port 8080"

# make the 'original' file
cp -n /opt/Teradici/thirdparty/tomcat/conf/server.xml /opt/Teradici/thirdparty/tomcat/conf/server.xml.orig

# add port 8080 http listener and make the 'info' page available at 'root' to not confuse L7 load balancers.
awk  '/<Service name=\"Catalina\">/{printf "<Service name=\"Catalina\">\n<Connector port=\"8080\" protocol=\"HTTP/1.1\" connectionTimeout=\"20000\" redirectPort=\"443\" />\n";next};{print}' \
 /opt/Teradici/thirdparty/tomcat/conf/server.xml.orig | \
awk '/xmlValidation=\"false\" xmlNamespaceAware=\"false\"/{print $0; print "<Context path=\"\" docBase=\"/opt/Teradici/thirdparty/tomcat/webapps/info\" />\n";next}1' \
 > /opt/Teradici/thirdparty/tomcat/conf/server.xml

echo "Finished setting up CM without SG"


# external IP is set and want to set up SG -> setup SG
if [ ${sge} = "true" ]; then
	if [ -n "$mypublicip" ]; then
		# first, enable sg in CM config and copy it back again
		awk '/^SecurityGatewayEnabled/{printf "SecurityGatewayEnabled = true\n";next};{print}'  /etc/ConnectionManager.conf >  ConnectionManager.conf
		cp -f ConnectionManager.conf /etc/ConnectionManager.conf

		# make the 'original' file one time only
		cp -n /etc/SecurityGateway.conf /etc/SecurityGateway.conf.orig
		awk -v externalip="$mypublicip" '/^ExternalRoutableIP/{printf "ExternalRoutableIP = %s\n",externalip;next};{print}' /etc/SecurityGateway.conf.orig > SecurityGateway.conf
		cp -f SecurityGateway.conf /etc/SecurityGateway.conf

		echo "Finished setting up SG"
	else
		echo "Enabling the security gateway but there is no detected public IP. Exiting."
		exit 1
	fi
fi


# restart all the services
service security_gateway restart
service connection_manager restart

# Hack... try to restart the CM again after 60 seconds to ensure that the info record is remapped to ROOT. This does not seem to be happening on its own.
sleep 60
service connection_manager restart


exit 0
