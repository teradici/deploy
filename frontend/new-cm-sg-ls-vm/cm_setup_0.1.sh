#!/bin/bash
#
# There must be one argument passed to this script.
# first argument is the FQDN of the broker.

#Update system to latest
yum -y update

#Install and setup the Sumo Collector
wget https://teradeploy.blob.core.windows.net/binaries/SC_1.0.zip -P /tmp/
unzip -o /tmp/SC_1.0.zip
rpm -i sumo/SumoCollector-19.182-25.x86_64.rpm
cp sumo/user.properties /opt/SumoCollector/config/
cp sumo/sumo_cm_vm.json /opt/SumoCollector/config/
echo "Attemtping to set sumo collector ID to: " "$2"
sed -i s/collectorID/"$2"/ /opt/SumoCollector/config/user.properties
# service collector install - configures the collector to start at boot time
service collector install
service collector restart
service collector status


#get the install zip files
wget https://teradeploy.blob.core.windows.net/binaries/CM-1.8_SG-1.14.zip -P /tmp/
unzip -o /tmp/CM-1.8_SG-1.14.zip

#remove unwanted jdk's
yum -y remove java-1.6.0-openjdk
yum -y remove java-1.7.0-openjdk

#open required ports
iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 8080 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 4172 -j ACCEPT
iptables -I INPUT 1 -p udp --dport 4172 -j ACCEPT
service iptables save


#get current networking configuration and use that for system setup. If there are dynamic IP's in the system THIS WILL EVENTUALLY FAIL.
mypublicip=$(dig +short myip.opendns.com @resolver1.opendns.com)
#alternates if opendns turns off: curl ipinfo.io/ip    curl ipecho.net/plain ; echo
myhostname=$(hostname)
myprivateip=$(ifconfig eth0 | awk '/inet addr/ {gsub("addr:", "", $2); print $2}')

echo "Detected hostname= $myhostname privateIP = $myprivateip publicip = $mypublicip"

#add local IP and name to hosts file.
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
           echo "no space in directoy name"
           ;;
esac

sh "$FOLDER_NAME"/cm_setup.sh

service security_gateway stop
service connection_manager stop

# modify CM setup
#make the 'original' file
cp -n /etc/ConnectionManager.conf /etc/ConnectionManager.conf.orig
awk -v broker="$1" '/^PcoipAddress/{printf "PcoipAddress = %s\n",broker;next};{print}' /etc/ConnectionManager.conf.orig > ConnectionManager.conf


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
	awk -v externalip="$mypublicip" '/^ExternalRoutableIP/{printf "ExternalRoutableIP = %s\n",externalip;next};{print}' /etc/SecurityGateway.conf.orig > SecurityGateway.conf
	cp -f SecurityGateway.conf /etc/SecurityGateway.conf

	echo "Finished setting up SG"
fi




#restart all the services
service security_gateway restart
service connection_manager restart

#Hack... try to restart the CM again after 60 seconds to ensure that the info record is remapped to ROOT. This does not seem to be happening on its own.
sleep 60
service connection_manager restart


exit 0



