# ShimCacheParser.py
#
# Andrew Davis, andrew.davis@mandiant.com
# Copyright 2012 Mandiant
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
#
# Identifies and parses Application Compatibility Shim Cache entries for forensic data.
import os
import sys
import csv
import binascii
import datetime
import struct
from xml.etree.ElementTree import *
import xml.parsers.expat
import zipfile
from base64 import b64decode
import getopt

#Values used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
CACHE_MAGIC_NT5_2 = 0xbadc0ffe
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

#Values used by Windows 6.1 (Win7 through Server 2008 R2)
CACHE_MAGIC_NT6_1 = 0xbadc0fee
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

#Values used by Windows 5.1 (WinXP 32-bit)
WINXP_MAGIC32 = 0xdeadbeef
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

g_verbose = False
output_header = ["Last Modified", "Last Update", "Path", "File Size", "Process Exec Flag"]

########
#Shim Cache format used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
########
class CACHE_ENTRY_NT5():
    def __init__(self, is32bit, data=None):
        self.is32bit = is32bit
        if data != None:
            self.update(data)
    def update(self, data):
        if self.is32bit:
            entry = struct.unpack('<2H 3L 2L', data)
        else:
            entry = struct.unpack('<2H 4x Q 2L 2L', data)
        self.wLength = entry[0]
        self.wMaximumLength = entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.dwFileSizeLow = entry[5]
        self.dwFileSizeHigh = entry[6]
    def size(self):
        if self.is32bit:
            return NT5_2_ENTRY_SIZE32
        else:
            return NT5_2_ENTRY_SIZE64

#########
#Shim Cache format used by Windows 6.1 (Win7 through Server 2008 R2)
#########
class CACHE_ENTRY_NT6():
    def __init__(self, is32bit, data=None):
        self.is32bit = is32bit
        if data != None:
            self.update(data)
    def update(self, data):
        if self.is32bit:
            entry = struct.unpack('<2H 7L', data)
        else:
            entry = struct.unpack('<2H 4x Q 4L 2Q', data)
        self.wLength = entry[0]
        self.wMaximumLength = entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.FileFlags = entry[5]
        self.Flags = entry[6]
        self.BlobSize = entry[7]
        self.BlobOffset = entry[8]
    def size(self):
        if self.is32bit:
            return NT6_1_ENTRY_SIZE32
        else:
            return NT6_1_ENTRY_SIZE64

################
# Usage
################
def usage():
    print \
        """
Input Options:
    -h, --help              Displays this message
    -b, --bin=BIN_FILE      Reads Shim Cache data from a binary BIN_FILE
    -m, --mir=XML           Reads Shim Cache data from a MIR XML file
    -z, --zip=ZIP_FILE      Reads ZIP_FILE containing MIR registry acquisitions
    -i, --hive=REG_HIVE     Reads Shim Cache data from a registry REG_HIVE
    -r, --reg=REG_FILE      Reads Shim Cache data from a .reg Registry export file
    -l, --local             Reads Shim Cache data from local system
Output Options:
    -o, --outfile=FILE      Writes to CSV data to FILE (default is STDOUT)
    -v, --verbose           Toggles verbose output"""

################
# Convert FILETIME to datetime.
################
def convert_filetime(dwLowDateTime, dwHighDateTime):
    try:
        date = datetime.datetime(1601, 1, 1, 0, 0, 0)
        temp_time = dwHighDateTime
        temp_time <<= 32
        temp_time |= dwLowDateTime
        return date + datetime.timedelta(microseconds=temp_time / 10)
    except OverflowError, err:
        return None

################
# Return a unique list while preserving ordering.
################
def unique_list(li):
    ret_list = []
    for entry in li:
        if entry not in ret_list:
            ret_list.append(entry)
    return ret_list

################
# Write the Log.
################
def write_it(rows, outfile=None):
    try:
        if not rows:
            print "[-] No data to write..."
            return
        if outfile == None:
            for row in rows:
                print " ".join(["%s" % x for x in row])
        else:
            print "[+] Writing output to %s..." % outfile
            try:
                writer = csv.writer(file(outfile, 'wb'), delimiter=',')
                writer.writerows(rows)
            except IOError, err:
                print "[-] Error writing output file: %s" % str(err)
                return
    except UnicodeEncodeError, err:
        print "[-] Error writing output file: %s" % str(err)
        return

#################
# Read the Shim Cache format, return a list of last modified dates/paths.
#################
def ReadCache(cachebin, quiet=False):
    if len(cachebin) < 16:
        #Data size less than minimum header size.
        return []
    try:
    #Get the format type
        magic = struct.unpack("<L", cachebin[0:4])[0]
        #This is a Windows 2k3/Vista/2k8 Shim Cache format, 
        if magic == CACHE_MAGIC_NT5_2:
            #Shim Cache types can come in 32-bit or 64-bit formats. We can determine this because 64-bit entries are serialized with u_int64 pointers.
            #This means that in a 64-bit entry, valid UNICODE_STRING sizes are followed by a NULL DWORD. Check for this here. 
            test_size = struct.unpack("<H", cachebin[8:10])[0]
            test_max_size = struct.unpack("<H", cachebin[10:12])[0]
            if (test_max_size - test_size) == 2 and (struct.unpack("<L", cachebin[12:16])[0]) == 0:
                if quiet == False:
                    print "[+] Found 64bit Windows 2k3/Vista/2k8 Shim Cache data..."
                entry = CACHE_ENTRY_NT5(False)
                return read_nt5_entries(cachebin, entry)

            #Otherwise it's 32-bit data.
            else:
                if quiet == False:
                    print "[+] Found 32bit Windows 2k3/Vista/2k8 Shim Cache data..."
                entry = CACHE_ENTRY_NT5(True)
                return read_nt5_entries(cachebin, entry)

        #This is a Windows 7/2k8-R2 Shim Cache.    
        elif magic == CACHE_MAGIC_NT6_1:
            test_size = struct.unpack("<H", cachebin[CACHE_HEADER_SIZE_NT6_1:CACHE_HEADER_SIZE_NT6_1 + 2])[0]
            test_max_size = struct.unpack("<H", cachebin[CACHE_HEADER_SIZE_NT6_1 + 2:CACHE_HEADER_SIZE_NT6_1 + 4])[0]

            #Shim Cache types can come in 32-bit or 64-bit formats. We can determine this because 64-bit entries are serialized with u_int64 pointers.
            #This means that in a 64-bit entry, valid UNICODE_STRING sizes are followed by a NULL DWORD. Check for this here. 
            if (test_max_size-test_size) == 2 and (struct.unpack("<L",cachebin[CACHE_HEADER_SIZE_NT6_1+4:CACHE_HEADER_SIZE_NT6_1+8])[0]) == 0:
                if quiet == False:
                    print "[+] Found 64bit Windows 7/2k8-R2 Shim Cache data..."
                entry = CACHE_ENTRY_NT6(False)
                return read_nt6_entries(cachebin, entry)
            else:
                if quiet == False:
                    print "[+] Found 32bit Windows 7/2k8-R2 Shim Cache data..."
                entry = CACHE_ENTRY_NT6(True)
                return read_nt6_entries(cachebin, entry)

        #This is WinXP cache data
        elif magic == WINXP_MAGIC32:
            if quiet == False:
                print "[+] Found 32bit Windows XP Shim Cache data..."
            return read_winxp_entries(cachebin)
        else:
            print "[-] Got an unrecognized magic value of 0x%x... bailing... " % magic
            return []

    except (RuntimeError, TypeError, NameError), err:
        print "[-] Error reading Shim Cache data: %s..." % err
        return []

##################
# Read Windows 2k3/Vista/2k8 Shim Cache entry formats.
##################
def read_nt5_entries(bin_data, entry):
    try:
        entry_list = []
        entry_size = entry.size()
        bad_entry_data = "N/A"
        contains_file_size = False
        executed = ""
        num_entries = struct.unpack("<L", bin_data[4:8])[0]
        if num_entries == 0:
            return []

        #On Windows Server 2008/Vista, the filesize is swapped out of this structure with two 4-byte flags.
        #Check to see if any of the values in "dwFileSizeLow" are larger than 2-bits. This indicates the entry contained file sizes.
        for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size), entry_size):
            entry.update(bin_data[offset:offset + entry_size])
            if entry.dwFileSizeLow > 3:
                contains_file_size = True
                break

        #Now grab all the data in the value.
        for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size), entry_size):
            entry.update(bin_data[offset:offset + entry_size])
            last_mod_date = convert_filetime(entry.dwLowDateTime, entry.dwHighDateTime)
            try:
                last_mod_date = last_mod_date.strftime("%m/%d/%y %H:%M:%S")
            except ValueError:
                last_mod_date = bad_entry_data
            path = bin_data[entry.Offset:entry.Offset + entry.wLength].decode('utf-16le', 'replace').encode('utf-8')
            path = path.replace("\\??\\", "")

            #It contains file data.
            if contains_file_size:
                hit = (last_mod_date, "N/A", path, str(entry.dwFileSizeLow), "N/A")
                if hit not in entry_list:
                    entry_list.append(hit)
            #It contains flags.
            else:
                #Check the CSRSS flag.
                if (entry.dwFileSizeLow & CSRSS_FLAG):
                    executed = "Yes"
                else:
                    executed = "No"
                hit = (last_mod_date, "N/A", path, "N/A", executed)
                if hit not in entry_list:
                    entry_list.append(hit)
        return entry_list
    except (RuntimeError, ValueError, NameError), err:
        print "[-] Error reading Shim Cache data: %s..." % err
        return []

##################
# Read the Shim Cache Windows 7/2k8-R2 entry format, return a list of last modifed dates/paths.
##################
def read_nt6_entries(bin_data, entry):
    try:
        entry_list = []
        entry_size = entry.size()
        num_entries = struct.unpack("<L", bin_data[4:8])[0]
        if num_entries == 0:
            return []
        file_executed = ""
        bad_entry_data = "N/A"

        #Walk each entry in the data structure. 
        for offset in range(CACHE_HEADER_SIZE_NT6_1, (num_entries * entry_size), entry_size):
            entry.update(bin_data[offset:offset + entry_size])
            last_mod_date = convert_filetime(entry.dwLowDateTime, entry.dwHighDateTime)
            try:
                last_mod_date = last_mod_date.strftime("%m/%d/%y %H:%M:%S")
            except ValueError:
                last_mod_date = bad_entry_data
            path = bin_data[entry.Offset:entry.Offset + entry.wLength].decode('utf-16le', 'replace').encode('utf-8')
            path = path.replace("\\??\\", "")

            #Test to see if the file may have been executed.
            if (entry.FileFlags & CSRSS_FLAG):
                file_executed = "Yes"
            else:
                file_executed = "No"

            hit = (last_mod_date, "N/A", path, "N/A", file_executed)

            if hit not in entry_list:
                entry_list.append(hit)
        return entry_list
    except (RuntimeError, ValueError, NameError), err:
        print "[-] Error reading Shim Cache data: %s..." % err
        return []

##################
# Read the WinXP Shim Cache data. Some entries can be missing data but still contain useful information,
# so try to get as much as we can.
##################
def read_winxp_entries(bin_data):
    entry_list = []
    bad_entry_data = "N/A"
    try:
        num_entries = struct.unpack("<L", bin_data[8:12])[0]
        if num_entries == 0:
            return []
        for offset in range(WINXP_HEADER_SIZE32, (num_entries * WINXP_ENTRY_SIZE32), WINXP_ENTRY_SIZE32):

            #No size size values are included in these entries, so search for utf-16 terminator.
            path_len = bin_data[offset:offset + (MAX_PATH + 8)].find("\x00\x00")
            #if path is corrupt, procede to next entry.
            if path_len == 0:
                continue
            path = bin_data[offset:offset + path_len + 1].decode('utf-16le').encode('utf-8')
            #Clean up the pathname.
            path = path.replace("\\??\\", "")
            if len(path) == 0: continue

            entry_data = (offset + (MAX_PATH + 8))
            #Get last mod time.
            last_mod_time = struct.unpack("<2L", bin_data[entry_data:entry_data + 8])
            try:
                last_mod_time = convert_filetime(last_mod_time[0], last_mod_time[1]).strftime("%m/%d/%y %H:%M:%S")
            except ValueError:
                last_mod_time = bad_entry_data
                #Get last file size.
            file_size = struct.unpack("<2L", bin_data[entry_data + 8:entry_data + 16])[0]
            if file_size == 0:
                file_size = bad_entry_data

            #Get last execution time.
            exec_time = struct.unpack("<2L", bin_data[entry_data + 16:entry_data + 24])
            try:
                exec_time = convert_filetime(exec_time[0], exec_time[1]).strftime("%m/%d/%y %H:%M:%S")
            except ValueError:
                exec_time = bad_entry_data
            hit = [last_mod_time, exec_time, path, file_size, "N/A"]
            if hit not in entry_list:
                entry_list.append(hit)
        return entry_list
    except (RuntimeError, ValueError, NameError), err:
        print "[-] Error reading Shim Cache data %s" % err
        return []

##################
# Get Shim Cache data from a registry hive.
##################
def read_from_hive(hive):
    out_list = []
    tmp_list = []

    #Check for dependencies.
    try:
        from Registry import Registry
    except ImportError:
        print "[-] Hive parsing requires Registry.py... Didn\'t find it, bailing..."
        sys.exit(2)

    try:
        reg = Registry.Registry(hive)
    except Registry.RegistryParse.ParseException, err:
        print "[-] Error parsing %s: %s" % (hive, err)
        sys.exit(1)

    top_lvl = reg.root().subkeys()
    for key in top_lvl:
        #Check each ControlSet.
        try:
            if "controlset" in key.name().lower():
                session_man_key = reg.open("%s\\Control\\Session Manager" % key.name())
                for subkey in session_man_key.subkeys():
                    #Read the Shim Cache structure.
                    if "appcompatibility" in subkey.name().lower() or "appcompatcache" in subkey.name().lower():
                        bin_data = str(subkey["AppCompatCache"].value())
                        tmp_list = ReadCache(bin_data)

                        if g_verbose:
                            for row in tmp_list:
                                row = list(row)
                                row.append(subkey.path())
                                if row not in out_list:
                                    out_list.append(row)
                        else:
                            for row in tmp_list:
                                if row not in out_list:
                                    out_list.append(row)

        except Registry.RegistryKeyNotFoundException:
            continue
    if len(out_list) == 0:
        return []
    else:
        #Add the header and return the list including duplicates.
        if g_verbose:
            out_list.insert(0, output_header + ["Key Path"])
            return out_list
        else:
        #Only return unique entries.
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

##################
# Get Shim Cache data from MIR registry output file.
##################
def read_mir(xml_file, quiet=False):
    out_list = []
    tmp_list = []

    #Open the MIR output file.
    try:
        tree = parse(xml_file)
        root = tree.getroot()
        for reg_item in root.findall("RegistryItem"):
            #Check to see that we have the right registry value.
            path_name = reg_item.find("Path").text
            if "control\\session manager\\appcompatcache\\appcompatcache" in path_name.lower() \
                or "control\\session manager\\appcompatibility\\appcompatcache" in path_name.lower():
                #return the base64 decoded value data.
                bin_data = b64decode(reg_item.find("Value").text)
                tmp_list = ReadCache(bin_data, quiet)

            if g_verbose:
                for row in tmp_list:
                    row = list(row)
                    row.append(path_name)
                    if row not in out_list:
                        out_list.append(row)
            else:
                for row in tmp_list:
                    if row not in out_list:
                        out_list.append(row)

    except (AttributeError, TypeError, IOError, xml.parsers.expat.error), err:
        print "[-] Error reading MIR XML: %s" % str(err)
        return []
    if len(out_list) == 0:
        return []
    else:
        #Add the header and return the list.
        if g_verbose:
            out_list.insert(0, output_header + ["Key Path"])
            return out_list
        else:
        #Only return unique entries.
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

##################
# Get Shim Cache data from .reg file.
#  Finds the first key named "AppCompatCache" and parses the
#  Hex data that immediately follows. It's a brittle parser,
#  but the .reg format doesn't change too often.
##################
def read_from_reg(reg_file, quiet=False):
    out_list = []

    if not os.path.exists(reg_file):
        return out_list
    f = open(reg_file, "rb")
    file_contents = f.read()
    f.close()
    # If the file was a direct export from regedit, etc, then it will be utf-16. If it was created with a script to
    # unite exports, then it will be ANSI. Exports for Windows 7 and Windows XP start with "Windows Registry Editor"
    if file_contents[0:23] != "Windows Registry Editor":
        try:
            file_contents = file_contents.decode("utf-16")
        except:
            pass
        if file_contents[0:23] != "Windows Registry Editor":
            print "[-] Unable to properly decode .reg file: %s" % reg_file
            return []

    path_name = None
    relevant_lines = []
    found_appcompat = False
    appcompat_keys = 0
    for line in file_contents.split("\r\n"):
        if "\"appcompatcache\"=hex:" in line.lower():
            relevant_lines.append(line.partition(":")[2])
            found_appcompat = True
        elif "\\appcompatcache]" in line.lower() or "\\appcompatibility]" in line.lower():
            # The Registry path is not case sensitive. Case will depend on export parameter.
            path_name = line.partition("[")[2].partition("]")[0]
            appcompat_keys += 1
        elif found_appcompat and "," in line:
            relevant_lines.append(line)
        elif found_appcompat and len(line) == 0:
            # begin processing a block
            hex_str = "".join(relevant_lines).replace("\\", "").replace(" ", "").replace(",", "")
            bin_data = binascii.unhexlify(hex_str)
            tmp_list = ReadCache(bin_data, quiet)

            if g_verbose:
                for row in tmp_list:
                    row = list(row)
                    row.append(path_name)
                    if row not in out_list:
                        out_list.append(row)
            else:
                for row in tmp_list:
                    if row not in out_list:
                        out_list.append(row)

            #reset variables for next block
            found_appcompat = False
            path_name = None
            relevant_lines = []

    if appcompat_keys <= 0:
        print "[-] Unable to find value in .reg file: %s" % reg_file
        return []

    if len(out_list) == 0:
        return []
    else:
        #Add the header and return the list.
        if g_verbose:
            out_list.insert(0, output_header + ["Key Path"])
            return out_list
        else:
        #Only return unique entries.
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

###################
# Acquire the current system's Shim Cache data.
###################
def get_local_data():
    tmp_list = []
    out_list = []
    global g_verbose

    try:
        import _winreg as reg
    except ImportError:
        print "[-] \'winreg.py\' not found... Is this a Windows system?"
        sys.exit(1)
    hReg = reg.ConnectRegistry(None, reg.HKEY_LOCAL_MACHINE)
    hSystem = reg.OpenKey(hReg, r'SYSTEM')
    for i in range(1024):
        try:
            control_name = reg.EnumKey(hSystem, i)
            if "controlset" in control_name.lower():
                hSessionMan = reg.OpenKey(hReg, "SYSTEM\\%s\\Control\\Session Manager" % control_name)
                for i in range(1024):
                    try:
                        subkey_name = reg.EnumKey(hSessionMan, i)
                        if "appcompatibility" in subkey_name.lower() or "appcompatcache" in subkey_name.lower():
                            appcompat_key = reg.OpenKey(hSessionMan, subkey_name)
                            bin_data = reg.QueryValueEx(appcompat_key, 'AppCompatCache')[0]
                            tmp_list = ReadCache(bin_data)

                            path_name = "SYSTEM\\%s\\Control\\Session Manager\\%s" % (control_name, subkey_name)
                            if g_verbose:
                                for row in tmp_list:
                                    row = list(row)
                                    row.append(path_name)
                                    if row not in out_list:
                                        out_list.append(row)
                            else:
                                for row in tmp_list:
                                    if row not in out_list:
                                        out_list.append(row)
                    except EnvironmentError:
                        break

        except EnvironmentError:
            break
    if len(out_list) == 0:
        return []
    else:
        #Add the header and return the list.
        if g_verbose:
            out_list.insert(0, output_header + ["Key Path"])
            return out_list
        else:
        #Only return unique entries.
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

###################
# Read a MIR XML zip archive.
###################
def read_zip(zip_name):
    zip_contents = []
    tmp_list = []
    final_list = []
    out_list = []
    hostname = ""

    try:
        #Open the zip archive.
        archive = zipfile.ZipFile(zip_name)
        for zip in archive.infolist():
            zip_contents.append(zip.filename)

        print "[+] Processing %d registry acquisitions..." % len(zip_contents)
        for item in zip_contents:
            try:
                if "_w32registry.xml" not in item:
                    continue
                filename = item.split('/')
                if len(filename) > 0:
                    filename = filename.pop()
                else:
                    continue
                    #Get the hostname from the MIR xml filename.
                hostname = '-'.join(filename.split('-')[:-3])
                xml_file = archive.open(item)

                #Catch possibly corrupt MIR XML data.
                try:
                    out_list = read_mir(xml_file, quiet=True)
                except(struct.error, xml.etree.ElementTree.ParseError), err:
                    print "[-] Error reading XML data from host: %s, data looks corrupt. Continuing..." % hostname
                    continue

                #Add the hostname to the entry list.
                if len(out_list) == 0:
                    continue
                else:
                    for out in out_list:
                        li = list(out)
                        if "Last Modified" not in li[0]:
                            li.insert(0, hostname)
                            final_list.append(li)

            except IOError, err:
                print "[-] Error opening file: %s in MIR archive: %s" % (item, err)
                continue
            #Add the final header.
        final_list.insert(0,("Hostname","Last Modified","Last Execution","Path","File Size","File Executed","Key Path"))
        return final_list

    except (IOError, zipfile.BadZipfile, struct.error), err:
        print "[-] Error reading zip archive: %s" % zip_name
        return []

###################
# Do the work.
###################
def main():
    try:
        if len(sys.argv) < 2:
            usage()
            sys.exit(1)
        opts, args = getopt.getopt(sys.argv[1:], "r:i:m:b:lvho:z:", ["reg=","hive=","mir=","bin=","local","verbose","help","output=","zip="])
    except getopt.GetoptError, err:
        print "[-] Argument error: %s" % str(err)
        usage()
        sys.exit(1)
    global g_verbose
    do_hive, do_reg, do_mir, do_zip, do_bin, do_local = False, False, False, False, False, False
    options = 0
    output_file = None

    for option, arg in opts:
        if option in ('-h', '--help'):
            usage()
            sys.exit(0)
        elif option in ('-i', '--hive'):
            do_hive = True
            param = arg
            options += 1
        elif option in ('-r', '--reg'):
            do_reg = True
            param = arg
            options += 1
        elif option in ('-m', '--mir'):
            do_mir = True
            param = arg
            options += 1
        elif option in ('-z', '--zip'):
            do_zip = True
            param = arg
            options += 1
        elif option in ('-b', '--bin'):
            do_bin = True
            param = arg
            options += 1
        elif option in ('-l', '--live'):
            do_local = True
            options += 1
        elif option in ('-o', '--output'):
            output_file = arg
        elif option in ('-v', '--verbose'):
            g_verbose = True

    if options > 1:
        print "[-] Error: only one input type can be specified at a time..."
        sys.exit(1)
    elif options == 0:
        usage()
        sys.exit(1)

    #Pull Shim Cache MIR XML.
    if do_mir:
        print "[+] Reading MIR output XML file: %s..." % param
        try:
            with file(param, 'rb') as xml_data:
                entries = read_mir(xml_data)
                if len(entries) <= 0:
                    print "[-] No data was found in the AppCompatCache value."
                    sys.exit(1)
                if len(entries) == 0:
                    print "[-] No Shim Cache entries found..."
                else:
                    write_it(entries, output_file)
        except IOError, err:
            print "[-] Error opening binary file: %s" % str(err)
            sys.exit(1)

    #Process a MIR XML ZIP archive
    elif do_zip:
        print "[+] Reading MIR XML zip archive: %s..." % param
        entries = read_zip(param)
        if len(entries) == 0:
            print "[-] No Shim Cache entries found..."
        else:
            write_it(entries, output_file)

    #Read the binary file.
    elif do_bin:
        print "[+] Reading binary file: %s..." % param
        try:
            with file(param, 'rb') as bin_data:
                bin_data = bin_data.read()
        except IOError, err:
            print "[-] Error opening binary file: %s" % str(err)
            sys.exit(1)
        entries = ReadCache(bin_data)
        if len(entries) == 0:
            print "[-] No Shim Cache entries found..."
        else:
            write_it(entries, output_file)

    #Read the key data from a registry hive.
    elif do_hive:
        print "[+] Reading registry hive: %s..." % param
        try:
            entries = read_from_hive(param)
            if len(entries) == 0:
                print "[-] No Shim Cache entries found..."
            else:
                write_it(entries, output_file)
        except IOError, err:
            print "[-] Error opening hive file: %s" % str(err)
            sys.exit(1)
    #Read the Shim Cache data from a .reg file
    elif do_reg:
        print "[+] Reading .reg file: %s..." % param
        entries = read_from_reg(param)
        if len(entries) == 0:
            print "[-] No Shim Cache entries found..."
        else:
            write_it(entries, output_file)
        pass
    #Read the local Shim Cache data from the current system
    elif do_local:
        print "[+] Dumping Shim Cache data from the current system..."
        entries = get_local_data()
        if len(entries) == 0:
            print "[-] No Shim Cache entries found..."
        else:
            write_it(entries, output_file)

if __name__ == "__main__":
    main()

    
    
    
    
    
    
    
