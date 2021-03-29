"""

File name: go_logger.py
Author: Alexander Hanel
Date Created: 20210328
Date Last Modified: 20210328
Python Version: Python 3.7 (I believe libptrace only runs under python27  & python3.7
Requirements: libptrace (https://github.com/immunityinc/libptrace)
Usage: python3.7 go_logger.py go_executable.exe everything.json
    - everything.json is generated via python gopep.py -st test\everything.exe

"""

import sys
import json
import os
import _ptrace
import argparse

DEBUG = True

def logger(cookie, string):
    print(string, end="")


def attached_handler(process):
    global functab
    for yy in functab:
        if "main.main" == functab[yy]:
            addr_mainmain = yy
    print("[{}] Attached".format(process.id))
    bp_main_main = _ptrace.breakpoint_sw(addr_mainmain, handler_mainmain)
    process.breakpoint_set(bp_main_main)
    print("[{}] BreakPoint Set at 0x{:08x}".format(process.id, addr_mainmain))


def handler_mainmain(breakpoint, thread):
    global functab
    for func in functab.keys():
        if "main.main" in functab[func]:
            continue
        bp_func = _ptrace.breakpoint_sw(func, handler_func)
        thread.process.breakpoint_set(bp_func)


def handler_func(breakpoint, thread):
    global functab
    retaddr = _ptrace.cconv.retaddr_get(thread)
    if "eip" in thread.registers:
        ip = thread.registers["eip"]
        sp = thread.registers["esp"]
        bp = thread.registers["ebp"]
    else:
        ip = thread.registers["rip"]
        sp = thread.registers["rsp"]
        bp = thread.registers["rbp"]
    func_ip = functab[ip]

    print("[{}] Func={}, IP=0x{:08x}, Frame=0x{:08x}, Base=0x{:08x}, Return=0x{:08x}".format(
        thread.process.id, func_ip,  ip, sp, bp, retaddr))


def process_exit(process):
    print("[{}] exited".format(process.id))


def thread_create(process, thread):
    print("[{}] Created thread with tid {}".format(process.id, thread.id))


def thread_exit(process, thread):
    print("[{}] Thread with tid {} exited".format(process.id, thread.id))


def module_load(process, module):
    print("[{}] Module {} loaded at 0x{:08x}".format(process.id, module.name, module.base))


def module_unload(process, module):
    print("[{}] Module {} unloaded".format(process.id, module.name))


def breakpoint(process, breakpoint, chance):
    print("[{}] Breakpoint".format(process.id))



def load_functab(config):
    with open(config) as f:
        data = json.load(f)
    temp = {}
    for func in data["functab"]:
        offset, name = func
        temp[offset] = name
    return temp


parser = argparse.ArgumentParser(description='Go Portable Executbale Function Hooker.')
parser.add_argument('file', nargs='?', metavar='filename', help='executable.')
parser.add_argument('json', nargs='?', metavar='json', help='json.')
parser.add_argument('args', nargs='*', metavar='args', help='arguments.')
parser.add_argument('--debug', '-d', action='store_true')
parser.add_argument('--second-chance', '-s', action='store_true')
args = parser.parse_args(sys.argv[1:])

if (not args.file or not args.json):
    parser.print_help()
    sys.exit(1)

if args.debug:
    _ptrace.log_hook_add(_ptrace.log_hook(logger))

handlers = _ptrace.event_handlers()
handlers.attached = attached_handler
handlers.process_exit = process_exit
handlers.thread_create = thread_create
handlers.thread_exit = thread_exit
handlers.module_load = module_load
handlers.module_unload = module_unload
handlers.breakpoint = breakpoint


options = 0
pp = os.path.join(os.path.dirname(sys.argv[0]), args.json)
functab = load_functab(pp)

if args.file:
    _ptrace.execv(args.file, args.args, handlers, options)

_ptrace.main()
