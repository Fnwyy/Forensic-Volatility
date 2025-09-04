# Case n°1 - Analyzing a Memory Dump with Volatility

**Objective:** Retrieve the name of a virtual machine from a memory dump using Volatility 3.

---

## Step 1: Enumerating registry hives

Volatility allows you to explore the Windows registry hives contained in the dump.

```bash
python3 vol.py -f /path/to/xxx.dmp windows.registry.hivelist.HiveList
```

This command displays all registry hives.

**Example output :**

Offset	FileFullPath	File output
0x8b20c008	\REGISTRY\MACHINE\SYSTEM	Disabled
0x8b23c008	\REGISTRY\MACHINE\HARDWARE	Disabled
0x8ee66008	\Device\HarddiskVolume1\Boot\BCD	Disabled
0x8ee66740	\SystemRoot\System32\Config\SOFTWARE	Disabled
0x90cab9d0	\SystemRoot\System32\Config\DEFAULT	Disabled
0x9670e9d0	??\C:\Users*\ntuser.dat	Disabled
0x9aad6148	\SystemRoot\System32\Config\SAM	Disabled
0x9ab25008	\SystemRoot\System32\Config\SECURITY	Disabled

> We focus on the **SYSTEM hive** because it contains the machine name.


---

## Step 2: Extracting the machine name

To extract the machine name, we use the `PrintKey` plugin:

```bash
python3 vol.py -f /path/to/xxx.dmp windows.registry.printkey.PrintKey --key “ControlSet001\\Control\\ComputerName\\ComputerName”
```

This command displays the value of the `ComputerName` key, which contains the computer name.

**Example output:**

| Key Path                                                                 | Type    | Value         |
| --------------------------------------------- --------------------------- | ------- | ------------- |
| \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName | REG\_SZ | “WIN-XXXXXXX” |

> The machine name is therefore `“WIN-XXXXXXX”`.

---

## ✅ Result

* SYSTEM hive identified
* `ComputerName` key extracted
* Machine name found

---

**Educational tip:**
You can use this method to explore any type of Windows memory dump and extract similar information (registry keys, system configurations, etc.)
