#!/bin/bash
#
# There must be three arguments passed to this script.
# first argument is the FQDN of the broker.
# second argument is the activation code for the license server

#get the install zip files
wget https://teradeploy.blob.core.windows.net/binaries/P-CM-1.6_SG-1.12.zip -P /tmp/
wget https://teradeploy.blob.core.windows.net/binaries/P-LS-1.1.0.zip -P /tmp/

