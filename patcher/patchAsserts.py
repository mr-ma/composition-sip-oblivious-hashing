from __future__ import print_function
from pwn import *
import sys, subprocess
import argparse
import mmap
import re
from shutil import copyfile
import os
try:
    from subprocess import DEVNULL # py3k
except ImportError:
    import os
    DEVNULL = open(os.devnull, 'wb')


def match_placeholders(console_reads):
    placeholderRegex = r'\$(-?\d+)\$(\d+)\$'

    rg = re.compile(placeholderRegex, re.IGNORECASE | re.MULTILINE | re.VERBOSE | re.DOTALL)
    matchobj = rg.findall(console_reads)
    return matchobj


def patch_binary(orig_name, new_name, args):
    expected_hashes = {}

    ldpreload = ["/home/dennis/Desktop/sip/self-checksumming/hook/build/libminm.so",
                 "/home/dennis/Desktop/sip/composition-framework/build/librtlib.so"]
    env = os.environ.copy()
    env['LD_PRELOAD'] = ":".join(ldpreload)
    cmd = [orig_name]
    stdin = None
    if args != '' and args.strip() != '':
        # set_args = "\'set args"
        # set_args += args
        # set_args += "\'"
        # cmd = ["gdb", "-ex", eval(set_args), "-x", script, orig_name]
        args_splitted = args.split()
        use_next_as_stdin = False
        for arg in args_splitted:
            if arg.startswith('<'):
                use_next_as_stdin = True
            elif use_next_as_stdin:
                stdin = open(arg.strip(), 'rb')
            else:
                cmd.append(arg.replace("\"", ""))

    result = subprocess.Popen(cmd,
                              stdin=stdin,
                              stdout=DEVNULL,
                              stderr=subprocess.PIPE,
                              env=env).communicate()[1]
    print(result)
    shrtnd_result = ""
    for line in result.splitlines():
        if line.startswith('#') or line.startswith('$'):
            shrtnd_result += line + "\n"
    # print shrtnd_result
    print("gdb ran. Parsing results")
    tuples = match_placeholders(shrtnd_result)
    for info in tuples:
        computed = int(info[0])
        placeholder = info[1]
        print("Computed " + info[1] + " " + info[0])
        expected_hashes[placeholder] = computed

    copyfile(orig_name, new_name)
    return expected_hashes


def find_placeholder(mm, search_bytes):
    addr = mm.find(search_bytes)
    if addr == -1:
        mm.seek(0)
    addr = mm.find(search_bytes)
    return addr


def patch_address(mm, addr, patch_value):
    mm.seek(addr, os.SEEK_SET)
    mm.write(patch_value)


def patch_placeholders(filename, placeholders, debug):
    print("patching placeholders")
    with open(filename, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), 0)
        patch_count = 0
        for placeholder in placeholders:
            expected_hash = placeholders[placeholder]
            if debug:
                print('Seeking to placeholder ' + placeholder + ' with expected hash ' + str(expected_hash))
            search_bytes = struct.pack("<q", long(placeholder))
            patch_value = struct.pack("<q", expected_hash)
            if debug:
                print('patch value ' + bytes(patch_value))
            address = find_placeholder(mm, search_bytes)
            if address == -1:
                print(str(placeholder) + ' placeholder not found')
            else:
                patch_count = patch_count + 1
            while address != -1:
                if debug:
                    print('Found placeholder ' + placeholder + ' at ' + hex(
                        address) + ' trying to patch it with ' + str(expected_hash))
                patch_address(mm, address, patch_value)
                address = find_placeholder(mm, search_bytes)
        return patch_count


def get_function_info(file_name, function_name):
    import r2pipe
    r2 = r2pipe.open(file_name)
    # find addresses and sizes of all functions
    r2.cmd("aa")
    r2.cmd("aac")
    function_list = r2.cmdj("aflj")
    found_func = filter(lambda function: function['name'] == 'sym.' + function_name, function_list)
    if len(found_func) > 0:
        address = r2.cmd("?p " + str(found_func[0]['offset']))
        return int(address, 16), found_func[0]['size']
    return -1, -1


def patch_block(file_name, address, size):
    nop_list = []
    for i in range(size - 1):
        nop_list.append(0x90)
    nop_bytes = struct.pack('B' * len(nop_list), *nop_list)
    print("Noping {} bytes @ {}".format(len(nop_bytes), hex(address)))
    with open(file_name, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), 0)
        mm.seek(address, os.SEEK_SET)
        mm.write(nop_bytes)


def patch_function(file_name):
    function_name = "oh_path_functions"
    # find the address and size of the function in the binary
    address, size = get_function_info(file_name, function_name)
    print(" oh_path_functions @" + hex(address), "  length:", str(size))
    if size > 1:
        patch_block(file_name, address, size)
    else:
        print('No functions to NOP')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', action='store', dest='binary', help='Binary name to patch using GDB')
    parser.add_argument('-n', action='store', dest='new_binary', help='Output new binary name after patching')
    parser.add_argument('-a', action='store', dest='assert_count',
                        help='Number of patches to be verified at the end of the process', required=False, type=int)
    parser.add_argument('-d', action='store', dest='debug', help='Print debug messages', required=False, type=bool,
                        default=False)
    parser.add_argument('-s', action='store', dest='oh_stats_file',
                        help='OH stats file to get the number of patches to be verified at the end of the process',
                        required=False)
    parser.add_argument('-g', action='store', dest='args', required=False, type=str, default='',
                        help='Running arguments to the program to patch')
    parser.add_argument('-p', action='store', dest='script', required=False, type=str,
                        default='/home/sip/sip-oblivious-hashing/assertions/gdb_script.txt',
                        help='gdb script to use when performing patching')
    parser.add_argument('-f', action='store', dest='finalize', help='Finalize binary by removing oh_path_functions',
                        required=False, type=bool, default=False)
    parser.add_argument('-m', action='store', dest='placeholders', help='Defines placeholders to be patched.', type=str,
                        default='')

    results = parser.parse_args()
    placeholders = patch_binary(results.binary, results.new_binary, results.args.strip("\""))

    if len(results.placeholders) > 0:
        with open(results.placeholders) as f:
            patch_info = [line.rstrip('\n') for line in f]

        result = {}
        import pprint
        pprint.pprint(placeholders)
        for t in patch_info:
            if t in placeholders:
                result[t] = placeholders[t]

        placeholders = result

    count_patched = patch_placeholders(results.new_binary, placeholders, results.debug)
    print("Patched:", count_patched, " in ", results.new_binary, " saved as:", results.new_binary)
    for placeholder in placeholders:
        print('Placeholder ' + str(placeholder) + ' expected hash ' + hex(placeholders[placeholder]))

    if results.oh_stats_file:
        import json
        from pprint import pprint
        oh_stats = json.load(open(results.oh_stats_file))
        assert_count = int(oh_stats["numberOfAssertCalls"])
        assert_count = assert_count + int(oh_stats["numberOfShortRangeAssertCalls"])
    else:
        assert_count = results.assert_count

    if assert_count > 0:
        # Verify that the number of patches is equal to the number of asserts in the binary
        if count_patched != assert_count:
            print('WARNING. Some asserts are not patched! Patched=', count_patched, " Asserts=", assert_count)
            # exit(1)
        else:
            print('Info. Patched=', count_patched, " Asserts=", assert_count)

    if results.finalize:
        ##NOP oh_path_functions
        patch_function(results.new_binary)


if __name__ == "__main__":
    main()
