IPMX NMOS Testing Package

This folder contains the IPMX NMOS Testing package. Follow these instructions to install the required python environment. These instructions assume a Windows environment but the test suite can also run under Linux if you change the Windows batch file for Linux scripts. For Windows use a regular Command Prompt; do NOT use PowerShell.

- Uncompress the archive into the folder IPMX-Testing-10

- Install the latest python3 executables on your system
- Install the GIT executables on your system
- Install the required python dependencies
- OPTIONAL (not used by IPMX tests) install sdpoker.  For Windows, install node.js and then “npm install -g sdpoker”
- OPTIONAL (not used by IPMX tests) install testssl. Following the instructions in the testssl\README.md file.

cd IPMX-Testing-10
python3 -m pip install -r requirements.txt

- Setup the IP address and port of your SENDER and RECEIVER DuT

copy IPMX-SETUP-MATROX.bat IPMX-SETUP-XYZ.bat
notepad IPMX-SETUP-XYZ.bat

set IPMX_REGISTRY_ADDRESS=IPv4 address of the registry in your environment
set IPMX_REGISTRY_PORT=Query port of the registry in your environment
set IPMX_SENDER_ADDRESS=IPv4 NMOS Control address of the SENDER DuT
set IPMX_SENDER_PORT=IPv4 NMOS Control port of the SENDER DuT
set IPMX_RECEIVER_ADDRESS=IPv4 NMOS Control address of the RECEIVER DuT
set IPMX_RECEIVER_PORT=IPv4 NMOS Control port of the RECEIVER DuT

- Setup the GUID of the NMOS audio and video Senders of the DuT

notepad ipmx-test-senders.guid

GUID-of-Video-Sender
GUID-of-Audio-Sender

- Setup the GUID of the NMOS audio and video Receiver of the DuT

notepad ipmx-test-receivers.guid

GUID-of-Video-Receiver
GUID-of-Audio-Receiver

- Setup the local UserConfig.py options

notepad nmostesting\UserConfig.py

# same as IPMX_REGISTRY_ADDRESS as a string
CONFIG.QUERY_API_HOST = '10.208.10.55'     

# same as IPMX_REGISTRY_PORT
CONFIG.QUERY_API_PORT = 8870

# IP address and port of your reference Sender
CONFIG.IS11_REFERENCE_SENDER_CONNECTION_API_URL = "http://10.208.10.64:5050/x-nmos/connection/v1.1/"
CONFIG.IS11_REFERENCE_SENDER_NODE_API_URL = "http://10.208.10.64:5050/x-nmos/node/v1.3/"

# Network interface connected to the media network (for PCAP capture)
MULTICAST_INTERFACE = "NIC3"

# Setup to a multicast address that is known not to be used by any DuT
MULTICAST_STREAM_TARGET=238.255.255.255

- Run IPMX-SETUP-XYZ.bat
- Run the IS-04 test suite on your Receiver

IS-04-01r.bat

- Run the IS-04 test suite on your Sender

IS-04-01s.bat

- Check for failures

The output of the test suite is sorted to have the FAILED tests printed last. There must be no failures and the test plan will indicate in which cases a status other than PASS is allowed.


