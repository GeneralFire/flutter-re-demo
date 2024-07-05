# src https://blog.lleavesg.top/article/Flutter-Reverse

# sample dump part
# {"method_name":"<optimized out>","offset":"0x0000000000014104","library_url":"0","class_name":"void"}
# {"method_name":"compareTo","offset":"0x0000000000000068","library_url":"dart:core","class_name":"_BigIntImpl"}
# {"method_name":"+","offset":"0x000000000000013c","library_url":"dart:core","class_name":"_BigIntImpl"}
# {"method_name":"Uint32List","offset":"0x0000000000014104","library_url":"dart:typed_data","class_name":"Uint32List"}

import json
import sys
import os
import json
import idaapi
import ida_kernwin
import idautils
import idc
import ida_funcs


count = 0
dup_offset = {}

function_info_file = "dart.json"
function_info_file = ida_kernwin.ask_file(
    False, f"*.json", "Flutter snapshot function name filename")


def replace_str(str):
    SMALL_FUNC_MAPPING = {
        " ": "__space__",
        "=": "__equals__",
        "|": "__or__",
        "&": "__and__",
        "^": "__xor__",
        "+": "__add__",
        "*": "__mul__",
        "-": "__sub__",
        "<": "__inf__",
        ">": "__sup__",
        "%": "__mod__",
        "/": "__fiv__",
        "~": "__bnot__",
    }
    replaced_string = ''.join(
        SMALL_FUNC_MAPPING.get(char, char) for char in str)
    return replaced_string


with open(function_info_file, "r") as file:
    lines = file.read().splitlines()

for line in lines:
    json_str = line.strip()
    count += 1
    try:
        data = json.loads(json_str)
        method_name = data["method_name"]
        offset = data["offset"]
        lib_name = data['library_url']
        class_name = data["class_name"]
        full_func_name = f"{class_name}::{method_name}"

        if offset not in dup_offset:
            dup_offset[offset] = [full_func_name]
        else:
            if full_func_name not in dup_offset[offset]:
                dup_offset[offset].append(full_func_name)

    except json.JSONDecodeError:
        print("Invalid JSON:", json_str)
        continue

exported_entries = {}
for entry in idautils.Entries():
    exported_entries[entry[3]] = entry[2]

base_addr = exported_entries['_kDartIsolateSnapshotInstructions']
offset_info = {}

func_name_count = {}
for each in dup_offset:
    if len(dup_offset[each]) == 1:
        func_addr = int(each, 16) + base_addr
        func_name = replace_str(dup_offset[each][0]).replace('#', "DIES")
        c = func_name_count.get(func_name, 0)
        if c == 0:
            func_name_count[func_name] = 1
        else:
            func_name_count[func_name] = c + 1
            func_name = f'{func_name}_{c}'

        offset_info[each] = dup_offset[each]
        if not ida_funcs.add_func(func_addr, idc.BADADDR):
            print(func_name + " : " + str(hex(func_addr)) +
                  " failed make function")
        given_name = idc.set_name(func_addr, func_name)

for each in offset_info:
    func_addr = int(each, 16) + base_addr
    if not ida_funcs.add_func(func_addr, idc.BADADDR):
        func_name = offset_info[each]
        print(str(func_name) + " : " + str(hex(func_addr)) +
              " failed make function again")


print('done')
