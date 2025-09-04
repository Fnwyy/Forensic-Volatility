# Case n°2 - Memory Dump Analysis with Volatility – Detecting a Malicious Process

**Objective:** Identify a malicious program in a memory dump and calculate the **MD5** hash of the absolute path to the malicious executable.  

## Step 1: Process Enumeration

First, list all running processes with Volatility:

``` bash
python3 vol.py -f /path/to/xxx.dmp windows.pslist
```

**Example output :**

| PID  | PPID | ImageFileName | Threads | CreateTime          |
| ---- | ---- | ------------- | ------- | ------------------- |
| 308  | 4    | smss.exe      | 29      | 2013-01-12 16:38:09 |
| 500  | 448  | winlogon.exe  | 111     | 2013-01-12 16:38:14 |
| 1220 | 560  | AvastSvc.exe  | 1180    | 2013-01-12 16:38:28 |
| 2548 | 2484 | explorer.exe  | 766     | 2013-01-12 16:40:27 |
| 2772 | 2548 | iexplore.exe  | 74      | 2013-01-12 16:40:34 |
| 3152 | 2548 | cmd.exe       | 23      | 2013-01-12 16:44:50 |
| 1136 | 2548 | iexplore.exe  | 454     | 2013-01-12 16:57:44 |


> Multiple `cmd.exe` and `iexplore.exe` instances are suspicious.

------------------------------------------------------------------------

## Step 2: Parent-Child Relationship Analysis

Use the `pstree` plugin to check parent-child process relations:

``` bash
python3 vol.py -f /path/to/xxx.dmp windows.pstree.PsTree | awk '{print $2, $3, $4, $5}' | grep -E "iexplore.exe|cmd.exe"
```

**Example output:**

    3152 2548 cmd.exe       0x87bf7030
    1136 2548 iexplore.exe  0x9549f678
    3044 1136 iexplore.exe  0x87d4d338
    2772 2548 iexplore.exe  0x87b6b030
    1616 2772 cmd.exe       0x89898030

> `explorer.exe` spawning `cmd.exe` and fake `iexplore.exe` processes is
> unusual.

------------------------------------------------------------------------

## Step 3: Inspecting Suspicious Processes

### Fake `iexplore.exe`:

``` bash
python3 vol.py -f /path/to/ch2.dmp windows.cmdline --pid 2772
```

    PID: 2772
    Process: iexplore.exe
    Args: "C:\Users\*\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe"

### Legitimate `iexplore.exe`:

``` bash
python3 vol.py -f /path/to/xxx.dmp windows.cmdline --pid 1136
```

    PID: 1136
    Process: iexplore.exe
    Args: "C:\Program Files\Internet Explorer\iexplore.exe"

> The malware hides under the name `iexplore.exe` but runs from
> **AppData**, not **Program Files**.

------------------------------------------------------------------------

## Step 4: MD5 Hash Calculation

``` python
import hashlib

path = r"C:\Users\*\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe"
md5_hash = hashlib.md5(path.encode()).hexdigest()
print(f"MD5: {md5_hash}")
```

**Example result:**

    49979149632639432397b3a1df8cb43d

✅ Case completed.

------------------------------------------------------------------------

📌 **Educational Tip:**\
This method illustrates how process enumeration, tree analysis, and command-line inspection can reveal malicious executables masquerading as legitimate ones in memory dumps.
