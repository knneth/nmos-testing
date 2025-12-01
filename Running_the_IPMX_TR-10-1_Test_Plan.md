# Running the IPMX TR-10 TP-1 Test Plan

This document provides step-by-step instructions for running the IPMX TR-10 test plan (VSF TR-10 TP-1). It assumes you have:

1. **Read the TP-1 document (VSF TR-10 TP-1)** that describes the test requirements and specifications
2. **Read the IPMX-README.txt** and completed the IPMX testing environment setup
3. **Configured your vendor-specific setup** using `IPMX-SETUP-XYZ.bat` (where XYZ is your vendor name)
4. **Set up the GUID files** for your Senders and Receivers in `IPMX_VENDOR_XYZ/`

**Note:** This test plan corresponds to VSF TR-10-TP-1, which validates compliance with the IPMX Technical Recommendations (TR-10 suite). The tests are organized according to the TP-1 document structure.

## Prerequisites Checklist

Before running tests, ensure:

- ✅ Python virtual environment is activated (`.venv\Scripts\activate.bat`)
- ✅ All dependencies are installed (`pip install -r requirements.txt`)
- ✅ Vendor setup script has been run (`IPMX-SETUP-XYZ.bat`)
- ✅ GUID files are configured:
  - `IPMX_VENDOR_XYZ\ipmx-test-senders.guid` (contains sender GUIDs, one per line)
  - `IPMX_VENDOR_XYZ\ipmx-test-receivers.guid` (contains receiver GUIDs, one per line)
- ✅ `nmostesting\UserConfig.py` is configured with correct IP addresses and ports
If testing a Sender
	- ✅ Wireshark is installed and configured (for PCAP analysis):
	  - RTP protocol enabled (`rtp_udp`)
	  - Time display format set to "Time as delta from previous packet"
	  - Lua dissector for IPMX RTCP Sender Reports installed
	If using the automated script to retreive the SDP and PCAP file
	- ✅ `start_capture_pcap.bat` is configured with dumpcap path or VB440 API URL

## Test Execution Overview

### GUID Configuration

A DuT may be tested against a video Profile and an audio Profile simultaneously or in sequence. In this document we use as an example the testing of a device against both a video Profile (uncompressed or JPEG XS) and an audio Profile (PCM or AM824). As such the `ipmx-test-senders.guid` file contains the GUID of the video Sender of the DuT and the GUID of the audio Sender of the DuT. The `ipmx-test-receivers.guid` file contains the GUID of the video Receiver of the DuT and the GUID of the audio Receiver of the DuT.


## Test Execution Workflow

### Phase 0: Verifying the configuration

- Run IPMX-SETUP-XYZ.bat to setup the environment. Make sure that the `IPMX_VENDOR` variable is set to your company name or a derivative of your company name such that you can easily identify the directory where the resulting SDP, PCAP, JSON and guid files are stored.

If testing a Receiver
	- Run IPMX-GUIDr.bat if you are testing Receivers of the DuT. You should observe among the listed Receiver's GUID those that you selected for testing the DuT and that are stored in the `ipmx-test-receivers.guid` file.

	- Activate the Receivers specified in the `ipmx-test-receivers.guid` file and for each of them have a Sender produce a stream for the Receiver to subscribe. Make sure Senders are streaming the streams and that your personal assessment is that the Receivers operate normally and are ready for testing.

If testing a Sender
	- Run IPMX-GUIDs.bat if you are testing Senders of the DuT. You should observe among the listed Sender's GUID those that you selected for testing the DuT and that are stored in the `ipmx-test-senders.guid` file.

	- Activate the Senders specified in the `ipmx-test-senders.guid` file and for each of them have a Receiver subscribe to the stream. Make sure Receivers are receiving the streams and that your personal assessment is that the Senders operate normally and are ready for testing.

	If you plan on using the automated script for retreiving the SDP and PCAP file used during these tests; verify the proper configuration of the system as follow.

	- Run IPMX-PCAPs.bat and verify the information listed as the capture test executes. The following lines describe the most important information displayed during the capture of the SDP and PCAP files. It is expected that a tool like the VB440 will be used for official IPMX testing but a LOCAL capture is also possible. The test operator must press any key after the capture of each PCAP file: after the video capture and after the audio capture. If using a tools like the VB440, the subscribed Receivers are those of the capture tool.

	  ```
	  Joining multicast group for sender ...
	  Successfully joined multicast group ...
	  Windows Interfaces ...
	  Windows NPF is ...
	  Started packet capture: video-*.pcap
	  Capturing on ...
	  File: IPMX_VENDOR_XYZ\video-*.pcap
	  Packets captured ...
	  Packets received/dropped on interface ...
	  IPMX_VENDOR_PCAP_CAPTURE is VB440
	  **Press any key to continue...**
	  Stopped packet capture: video-*.pcap

	  video SDP transport file displayed here ...

	  Left multicast group ...

	  Joining multicast group for sender ...
	  Successfully joined multicast group ...
	  Windows Interfaces ...
	  Windows NPF is ...
	  Started packet capture: audio-*.pcap
	  Capturing on ...
	  File: IPMX_VENDOR_XYZ\audio-*.pcap
	  Packets captured ...
	  Packets received/dropped on interface ...
	  IPMX_VENDOR_PCAP_CAPTURE is VB440
	  **Press any key to continue...**

	  Stopped packet capture: audio-*.pcap

	  audio SDP transport file displayed here ...

	  Left multicast group ...
	  ```

	- Verify that the displayed SDP files match with those stored in the IPMX_VENDOR_XYZ directory and correspond to the actual configuration of the video and audio streams.

	- Use Wireshark to open both the video and audio PCAP files and make sure there are a minimum of 10 RTCP IPMX Sender Reports in each PCAP file. If there are not enough RTCP Sender Reports, edit `start_capture_pcap.bat` to increase the `packetLimit` value in the curl command (default is 6000 for video and 1000 for audio) or increase the `-c` parameter for LOCAL capture mode.

- You are now ready to proceed with the TP-1 Test Plan.

### Phase 1: IPMX Manual Testing

Follow the manual tests described in TP-1 sections 11 to 16 inclusively with the exception of section 13.1, 13.2 and 13.3 that are automatically tested during Phase 2.

### Phase 2: IPMX Automatic Testing for Senders
Python scripts are used to verify conformance to TP-1 section 13. For a given format described in a cfg file the SDP file is retreived from the Sender.
A PCAP file of the stream from the Sender is then analyzed and compared to the SDP file and cfg file to test conformance.
There is a automated script IPMX-PCAPs.bat that retreives the SDP file and captures a PCAP file automatically.
It does this using either the network card of the computer used to run the test script or a VB440 device.
The steps are described further down. Alternatively the retreival of the SDP file and capture of the PCAP file can be done manually.

Manual Capture:
The test scripts for section 13 rely on the PCAP capture coresponding to the moment the stream is first activated. When doing the aquisition of the PCAP file manually the sugested methodology is:
- Disable the Sender under test.
- Start the Capture process. 
- Activate the Sender under test.
- Stop the Capture.
Make sure the captured file contains at least 10 RTCP Sender Reports. IMPORTANT: Seperate PCAP file should be captured for Video and for Audio.
The name of the SDP file and PCAP file stored do not need to match the name generated by automated test script.
The instruction contained in this document do assume those names.

Automated Capture:
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory
    - Capture PCAP and SDP files for the Senders of the DuT:

   ```batch
   IPMX-PCAPs.bat
   ```

    - Check the information displayed during the capture operation to make sure the process completed successfully.

        **Important Notes:**
        - **The DuT must be actively streaming** before running this script
        - This script will:
            - Capture PCAP files for video and audio streams
            - Capture SDP transport files for video and audio streams
            - Save files to `IPMX_VENDOR_XYZ\` directory
            - When using LOCAL capture mode, the script uses the interface IP from `CONFIG.MULTICAST_INTERFACE` in `UserConfig.py`

        **Output Files:**
        - `IPMX_VENDOR_XYZ\video-<guid>.pcap` - Video stream PCAP
        - `IPMX_VENDOR_XYZ\audio-<guid>.pcap` - Audio stream PCAP
        - `IPMX_VENDOR_XYZ\video-<guid>.sdp` - Video SDP file
        - `IPMX_VENDOR_XYZ\audio-<guid>.sdp` - Audio SDP file


1. **Section 13.1 Tests**

   ```batch
   python TP-10-1Sec13.1.py cfg\Test*.cfg IPMX_VENDOR_XYZ\video-*.pcap
   python TP-10-1Sec13.1.py cfg\Test*.cfg IPMX_VENDOR_XYZ\audio-*.pcap
   ```

2. **Section 13.2 Tests**

   ```batch
   python TP-10-1Sec13.2.py cfg\Test*.cfg IPMX_VENDOR_XYZ\video-*.sdp
   python TP-10-1Sec13.2.py cfg\Test*.cfg IPMX_VENDOR_XYZ\audio-*.sdp
   ```

3a. **Section 13.3a Tests**

   ```batch
   python TP-10-1Sec13.3a.py IPMX_VENDOR_XYZ\video-*.pcap IPMX_VENDOR_XYZ\video-*.sdp
   python TP-10-1Sec13.3a.py IPMX_VENDOR_XYZ\audio-*.pcap IPMX_VENDOR_XYZ\audio-*.sdp
   ```

3b. **Section 13.3b Tests**

   ```batch
   python TP-10-1Sec13.3b.py cfg\Test*.cfg IPMX_VENDOR_XYZ\video-*.pcap
   python TP-10-1Sec13.3b.py cfg\Test*.cfg IPMX_VENDOR_XYZ\audio-*.pcap
   ```

### Phase 3: NMOS API Compliance Testing

These tests verify that your Device Under Test (DuT) correctly implements the NMOS APIs.

1. **IS-04 Node API Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   IS-04-01s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   IS-04-01r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

2. **IS-05 Connection Management Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   IS-05-01s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   IS-05-01r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

3. **IS-05 Interaction with IS-04**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   IS-05-02s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   IS-05-02r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

4. **IS-11 Stream Compatibility Tests**

    - For HDMI, use a source that follows the preferred mode of the EDID.
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   IS-11-01s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)
   - The results are saved in IPMX_VENDOR_XYZ\IS-11-01s.json
   - According to the testing configuration run an IPMX-CHECK script. The configuration is described as having inputs, outputs or none, supporting EDID or not, etc.
   - The FINAL VERDICT of the IPMX-CHECK script indicates whether the DuT passes or fails the IS-11 tests.

   ```batch
   IPMX-CHECK-HDMI-IS11s.bat
   ```

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.
   - Make sure the reference or preferred Senders are properly configured in the UserConfig.py file

    - Test the Receivers of the DuT:
   ```batch
   IS-11-01r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)
   - The results are saved in IPMX_VENDOR_XYZ\IS-11-01r.json
   - According to the testing configuration run an IPMX-CHECK script. The configuration is described as having inputs, outputs or none, supporting EDID or not, etc.
   - The FINAL VERDICT of the IPMX-CHECK script indicates whether the DuT passes or fails the IS-11 tests.

   ```batch
   IPMX-CHECK-HDMI-IS11r.bat
   ```

5. **SDP Validation Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   IPMX-SDPs.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   IPMX-SDPr.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

6. **Sender and Receiver Capabilities Tests**

    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   BCP-004-02s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   BCP-004-01r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

7. **Compressed Stream Profile Tests**

    - JPEG XS
        - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory for a JPEG XS video stream.

        - Test the Senders of the DuT:
        ```batch
        BCP-006-01s.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

        - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory for a JPEG XS video stream and have the Receivers of the DuT subscribe to the streams.

        - Test the Receivers of the DuT:
        ```batch
        BCP-006-01r.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

    - H.264
        - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory for an H.264 video stream.

        - Test the Senders of the DuT:
        ```batch
        BCP-006-02s.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

        - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory for an H.264 video stream and have the Receivers of the DuT subscribe to the streams.

        - Test the Receivers of the DuT:
        ```batch
        BCP-006-02r.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

    - H.265 / HEVC
        - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory for an H.265 video stream.

        - Test the Senders of the DuT:
        ```batch
        BCP-006-03s.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

        - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory for an H.265 video stream and have the Receivers of the DuT subscribe to the streams.

        - Test the Receivers of the DuT:
        ```batch
        BCP-006-03r.bat
        ```
        - Results are sorted with FAILED tests printed last
        - Review output for any failures (some may be expected per test plan)

8. **Multicast Tests**

    - Configure the multicast address and port of the DuT to the default requirements of IPMX.
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   IPMX-MCASTs.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)
   - The multicast address and port of the DuT must be re-configured after this test.

    - Activate reference or preferred Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   IPMX-MCASTr.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)

9. **HKEP Capability Tests**

    - Disable the PEP feature of the DuT
    - Connect an HDCP compliant source to the inputs of the DuT
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   BCP-005-02s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)
   - Assess that the Senders are transmitting to reference Receivers without disruptions.

    - Disable the PEP feature of the DuT
    - Connect an HDCP compliant monitor to the outputs of the DuT
    - Activate reference or preferred HKEP Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   BCP-005-02r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)
   - Assess that the Receivers are receiving from reference Senders without disruptions.

    TODO: add hkep dissector testing using various PCAP from various configurations.

10. **PEP Capability Tests**

    - If PEP is not supported along with HKEP disable the HKEP feature.
    - Activate the Senders of the DuT, each one using a configuration from the `cfg` directory

    - Test the Senders of the DuT:
   ```batch
   BCP-005-03s.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)
   - Assess that the Senders are transmitting to reference Receivers without disruptions.

    - If PEP is not supported along with HKEP disable the HKEP feature.
    - Activate reference or preferred PEP Senders, each one using a configuration from the `cfg` directory and have the Receivers of the DuT subscribe to the streams.

    - Test the Receivers of the DuT:
   ```batch
   BCP-005-03r.bat
   ```
   - Results are sorted with FAILED tests printed last
   - Review output for any failures (some may be expected per test plan)
   - Assess that the Receivers are receiving from reference Senders without disruptions.

    TODO: add pep dissector testing using various PCAP from various configurations.

## Important Notes

1. **Device State**: In general, the DuT must be **configured and activated prior to each test**. Both Senders and Receivers must be streaming. There are a few exceptions where tests may request inactive devices - in those cases, first run with them active, then deactivate and rerun the test.

2. **Test Results**: The output of NMOS test suites is sorted to have FAILED tests printed last. Review all failures carefully - the TP-1 document will indicate in which cases a status other than PASS is allowed.

3. **Configuration Files**: The `cfg\` directory contains configuration files for different test scenarios. Select the appropriate `.cfg` file based on:
   - Video format (1080p, UHD)
   - Frame rate (50, 59, 60)
   - Color space (YUV, RGB8)
   - Audio format (L16, L24)
   - Channel count (1, 2, 8)
   - PTP usage (files with "PTP" suffix)

4. **PTP Testing**: Tests should be performed both with and without a PTP Grandmaster present on the network, as specified in TP-1 Section 9.

5. **Command Prompt**: Use a regular Windows Command Prompt to run batch files, **do NOT use PowerShell**.

---

*This IPMX testing environment is a work-in-progress. Bug reports and suggestions to make it better are welcome.*

