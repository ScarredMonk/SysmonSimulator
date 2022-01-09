# SysmonSimulator
SysmonSimulator is an Open source Windows event simulation utility created in C language, that can be used to simulate most of the attacks using WINAPIs. This can be used by Blue teams for testing the EDR detections and correlation rules. I have created it to generate attack data for the relevant Sysmon Event IDs.

## Blogpost: 
This tool has been explained in the blogpost:
https://rootdse.org/posts/understanding-sysmon-events/

Attacks are covered for important Windows events as follows: 

- **Process Events**: Process Creation, Process Termination, Process Access
- **File Events**: File Create, File Create Time Change, File Stream Creation Hash, File Delete, File Delete Detected
- **Named Pipes Events**: Named Pipe Creation, Named Pipe Connect events
- **Registry Actions**: Registry Object create and delete, Value Set, Key and Value Rename
- **Image Loading**
- **Network Connections**
- **Create Remote Thread**
- **Raw Access Read**
- **DNS Query**
- **WMI Events**
- **Clipboard Capture**
- **Process Image Tampering**

```
 __                        __
(_      _ ._ _   _  ._    (_  o ._ _      |  _. _|_  _  ._
__) \/ _> | | | (_) | |   __) | | | | |_| | (_|  |_ (_) |
    /
                                            by @ScarredMonk

Sysmon Simulator v0.1 - Sysmon event simulation utility
    A Windows utility to simulate Sysmon event logs

Usage:
Run simulation : .\SysmonSimulator.exe -eid <event id>
Show help menu : .\SysmonSimulator.exe -help

Example:
SysmonSimulator.exe -eid 1

Parameters:
-eid 1  : Process creation
-eid 2  : A process changed a file creation time
-eid 3  : Network connection
-eid 5  : Process terminated
-eid 6  : Driver loaded
-eid 7  : Image loaded
-eid 8  : CreateRemoteThread
-eid 9  : RawAccessRead
-eid 10 : ProcessAccess
-eid 11 : FileCreate
-eid 12 : RegistryEvent - Object create and delete
-eid 13 : RegistryEvent - Value Set
-eid 14 : RegistryEvent - Key and Value Rename
-eid 15 : FileCreateStreamHash
-eid 16 : ServiceConfigurationChange
-eid 17 : PipeEvent - Pipe Created
-eid 18 : PipeEvent - Pipe Connected
-eid 19 : WmiEvent - WmiEventFilter activity detected
-eid 20 : WmiEvent - WmiEventConsumer activity detected
-eid 21 : WmiEvent - WmiEventConsumerToFilter activity detected
-eid 22 : DNSEvent - DNS query
-eid 24 : ClipboardChange - New content in the clipboard
-eid 25 : ProcessTampering - Process image change
-eid 26 : FileDeleteDetected - File Delete logged

Description:
Enter an event ID from the above parameters list and the related Windows API function is called
to simulate the attack and Sysmon event log will be generated which can be viewed in the Windows Event Viewer

Prerequisite:
Sysmon must be installed on the system
```

