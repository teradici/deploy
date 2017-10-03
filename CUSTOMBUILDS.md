In order to deploy a custom build of the Cloud Access Manager POC, Azure will need access to the templates and binaries to deploy the solution.

Binaries are pulled in from outside of GitHub to avoid the repo getting massive. So there are two locations from which things are grabbed:
-	The Github repo for the json templates and some of the scripts – pointed to by the "_artifactsLocation" parameter
-	The binary (blob) source for the rest of the installers and such – pointed to by the “CAMDeploymentBlobSource” parameter

Look at azuredeploy.json, to see the current default location.

To test new scripts and templates, you can mirror the code to any location that is publicly available and follows the same directory tree.

As an example, if you are branching in the same github repo, for example, just insert the branch name for ‘master’ in this link:

"https://raw.githubusercontent.com/teradici/deploy/master/dev/domain-controller"

And use the modified link for ‘_artifactsLocation’

To pull in different binaries, change the URI for “CAMDeploymentBlobSource.”

The system currently needs the following files in the CAMDeploymentBlobSource store:
* apache-tomcat-8.0.39-windows-x64.zip
* CloudAccessManager.war
* Install-BR.ps1.zip
* Install-CAM.ps1.zip
* jdk-8u91-windows-x64.exe
* server2016-standard-agent.json
* pcoip-broker.war
* P-CM-1.6_SG-1.12.zip (*)
* P-LS_1.1.0.zip (*)
* PCoIP_agent_release_installer_2.7.0.4060_standard.exe (*)
* Install-DC-and-CA.ps1.zip (*)
* .keystore (**)
* Firefox Setup Stub 49.0.1.exe (**)

Some of these locations are hard-coded in the deployment scripts to https://teradeploy.blob.core.windows.net/binaries regardless of the setting. These are marked with (*). Items marked with (**) may need to be in both locations. Neither this list, nor the (*)’s and (**)’s have been verified.

If you need to modify a component which has a (*) or (**) then you’ll want to ensure the templates and scripts respect the location/source parameters in the parameters template first. And then update this list.

Open issues:
-	Clearly the respecting the location/source URI problem has to be fixed.
-	_artifactsLocationSasToken is also not respected through the whole deployment so if you are pulling from a private location, that will have to be addressed.
