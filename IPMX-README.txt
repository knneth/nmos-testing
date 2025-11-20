IPMX NMOS Testing Package
=========================

This folder contains the IPMX NMOS Testing package. Follow these instructions to install the required Python environment. These instructions assume a Windows environment but the test suite can also run under Linux if you change the Windows batch file for Linux scripts. For Windows use a regular Command Prompt to run the batch files, do NOT use PowerShell.

- Uncompress the archive into the folder IPMX-Testing-13

- Install the latest Python 3 executables on your system (Python 3.12 has been validated)
- Install the GIT executables on your system (Git 2.17.1 has been validated)
- Create a Python virtual environment
    cd IPMX-Testing-13
    python3 -m venv .venv
    .venv\Scripts\activate.bat
- Install the required Python dependencies
    cd IPMX-Testing-13
    python3 -m pip install -r requirements.txt
- OPTIONAL (not used by IPMX tests) install sdpoker. For Windows, install Node.js and then run: npm install -g sdpoker
- OPTIONAL (not used by IPMX tests) install testssl by following the instructions in the testssl\README.md file.

- Set up your VENDOR directory and the IP address and port of your DuT. The testing environment supports per-API IP address and port. Edit the IPMX-SETUP-XYZ.bat to get all the details.

    copy IPMX-SETUP-MATROX.bat IPMX-SETUP-XYZ.bat

    notepad IPMX-SETUP-XYZ.bat
        set IPMX_REGISTRY_ADDRESS=IPv4 address of the registry in your environment
        set IPMX_REGISTRY_PORT=Query port of the registry in your environment
        set IPMX_SENDER_ADDRESS=IPv4 NMOS Control address of the SENDER DuT
        set IPMX_SENDER_PORT=IPv4 NMOS Control port of the SENDER DuT
        set IPMX_RECEIVER_ADDRESS=IPv4 NMOS Control address of the RECEIVER DuT
        set IPMX_RECEIVER_PORT=IPv4 NMOS Control port of the RECEIVER DuT
        set IPMX_VENDOR=XYZ
        set IPMX_VENDOR_PCAP_CAPTURE=LOCAL or VB440

    IPMX-SETUP-XYZ.bat

    If you have multiple configurations to test and require separate VENDOR directories, create multiple SETUP files as IPMX-SETUP-XYZ-option1.bat

- Note that the captured PCAP and SDP files will be written to the vendor directory

- Set up the GUID of the NMOS audio and video Senders of the DuT.

    notepad IPMX_VENDOR_XYZ\ipmx-test-senders.guid

- To help you get the GUID of your senders, run the following scripts and copy/paste the appropriate GUID, one per line.

    IPMX-GUIDs.bat

- Set up the GUID of the NMOS audio and video Receiver of the DuT

    notepad IPMX_VENDOR_XYZ\ipmx-test-receivers.guid

- To help you get the GUID of your receivers, run the following scripts and copy/paste the appropriate GUID, one per line.

    IPMX-GUIDr.bat

- Set up the local UserConfig.py options

    notepad nmostesting\UserConfig.py

    # same as IPMX_REGISTRY_ADDRESS as a string
    CONFIG.QUERY_API_HOST = '10.208.10.55'     

    # same as IPMX_REGISTRY_PORT
    CONFIG.QUERY_API_PORT = 8870

    # IP address and port of the reference Sender to be used for IS-11 testing of the Receivers
    CONFIG.IS11_REFERENCE_SENDER_CONNECTION_API_URL = "http://10.20.10.64:5050/x-nmos/connection/v1.1/"
    CONFIG.IS11_REFERENCE_SENDER_NODE_API_URL = "http://10.20.10.64:5050/x-nmos/node/v1.3/"

    # IP address of the Network interface connected to the media network (for PCAP capture)
    CONFIG.MULTICAST_INTERFACE = "10.20.10.61"

    # Setup to a multicast address that is known not to be used by any DuT
    CONFIG.MULTICAST_STREAM_TARGET=239.1.0.100

- Setup the PCAP capture script start_capture_pcap.bat

    Set the path to the dumpcap program. Ex. C:\Program Files\Wireshark\dumpcap
    Set the IP address of the VB440 probe api. Ex. https://192.168.112.57/probe/api/captures

    You may need to adjust the number of packets captured. By default 6000 for video and 1000 for audio.

    !!! Note that you need to press a key when the message "Press any key to continue..." appears right after displaying "IPMX_VENDOR_PCAP_CAPTURE is ..."

    !!! Note that the script now gets the LOCAL interface as a parameter.

- Run IPMX-SETUP-XYZ.bat

- Run the IS-04 test suite on your Receiver

IS-04-01r.bat

- Run the IS-04 test suite on your Sender

IS-04-01s.bat

- Check for failures

The output of the test suite is sorted to have the FAILED tests printed last. There must be no failures and the test plan will indicate in which cases a status other than PASS is allowed.

- Activate your Sender and capture an SDP transport file and a PCAP for analysis

IPMX-PCAPs.bat

Check IPMX_VENDOR_XYZ for the resulting files.

- In general the DuT must be configured and activated prior to each test. Both Senders and Receivers must be streaming. There are a few exceptions where the test may request the Senders and Receivers to be inactive. In those cases first run with them active and then deactivate them and rerun the test to get all the results.

- PCAP analysis scripts require proper Wireshark configuration as they depend on tshark:

    Active Protocols:
    - RTP: Enable rtp_udp

    Time Display Format:
    - Set to "Time as delta from previous packet"

    Additional Setup:
    - Install Lua dissector for IPMX RTCP Sender Reports

- IS-11 test results

There are new batch files for the analysis of the IS-11 test results targeting specific environments. The examples provided are IPMX-CHECK-HDMI-IS11s.bat and IPMX-CHECK-HDMI-IS11r.bat. Additional ones can be created for SDI and for scenarios without Input or Outputs.

- This IPMX testing environment is a work-in-progress. Your bug reports and suggestions to make it better are welcome.
