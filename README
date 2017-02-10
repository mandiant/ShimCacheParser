ShimCacheParser.py v1.0
====================

ShimCacheParser is a proof-of-concept tool for reading the Application Compatibility Shim Cache stored in the Windows registry. Metadata of files that are executed on a Windows system are placed within this data structure on the running system. Upon system shutdown, this data structure is serialized to the registry in one of two registry paths depending on the operating system version (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache or HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache) . The format of this data, as well as the types of information stored also vary between operating system which is summarized below:
    -Windows XP 32-bit: File Path, $STANDARD_INFORMATION Last Modified Time, File Size, and Last Update Time
    -Windows 2003 and XP 64-bit: File Path, $STANDARD_INFORMATION Last Modified Time, and File Size
    -Windows Vista and later: File Path, $STANDARD_INFORMATION Last Modified Time, Shim Flags

More information about this cache and how it's implemented can be found here: https://www.fireeye.com/content/dam/fireeye-www/services/freeware/shimcache-whitepaper.pdf

The script will find these registry paths, automatically determine their format, and return the data in an optional CSV format. During testing it was discovered that on Windows Vista and later, files may be added to this cache if they were browsed to by explorer.exe and never actually executed.  When these same files were executed, the 2nd least significant bit in the flags field was set by the CSRSS process while checking SXS information. During testing it was possible to identify if processes were executed based on this flag being set. This flag's true purpose is currently unknown and is still being testing for consistency, so it should not be currently used to definitively conclude that a file may or may not have executed. 

Usage
====================
ShimCacheParser.py requires python 2.x (2.6 or later) which can be obtained from http://www.python.org/download/. Parsing of exported registry hives requires Willi Ballenthin's python-registry library which is currently included in this project or can be downloaded here: https://github.com/williballenthin/python-registry. 

Several types of inputs are currently supported:
    -Extracted Registry Hives (-i, --hive)
    -Exported .reg registry files (-r, --reg) 
    -MIR XML  (-m, --mir)
    -Mass MIR registry acquisitions ZIP archives (-z, --zip)
    -The current Windows system (-l, --local)
    -Exported AppComatCache data from binary file (-b, --bin)
    
The output CSV file is set with the (-o, --output) argument. If no output file is specified, the data will be printed to STDOUT.  ShimCacheParser will search each ControlSet and will only return unique entries by default. If you want to display duplicates as well as the full registry path where the data was taken use the verbose (-v, --verbose) option. 
