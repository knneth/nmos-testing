REM for local computer capture
REM "\Program Files\Wireshark\dumpcap" -q -i 9 -B 256 -c 3000 -w %1 -f "ip and host %2"

REM for VB440 capture
REM for /f "usebackq delims=" %%i in (`ssh capture@10.20.10.194 "capture/capture.mjs %2 5004 2110-20 | tail -n1"`) do curl -LRs %%i -o %1
for /f "usebackq delims=" %%i in (`ssh capture@10.20.10.194 "capture/capture.mjs %2 %3 %4 | tail -n1"`) do curl -LRs %%i -o %1
pause
