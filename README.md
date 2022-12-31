# Script-Enforcer-Bypass
A Garry's Mod Script Enforcer bypass to allow `lua_openscript_cl` commands to execute. 

* 💫 Easy to use
* 💡 Simple and safe
* 💥 64-bit and 32-bit support

# Recommended Installation (Using Python) 🐍

1. Copy `steamapps\common\GarrysMod\garrysmod\bin\client.dll` (x86) or `steamapps\common\GarrysMod\bin\win64\client.dll` (x64) to the current directory.
2. Run `python patch.py` (get [Python3](https://www.python.org/downloads/) here).
3. Copy the patched `client.dll` into `steamapps\common\GarrysMod\garrysmod\bin\client.dll` (x86) or `steamapps\common\GarrysMod\bin\win64\client.dll` (x64).
4. Start Garry's Mod.
5. Load scripts from your `lua/` directory with `lua_openscript_cl <filename>` using the console.

# Easy Installation

[Get the latest .dll from the releases page.](https://github.com/qubard/Script-Enforcer-Bypass/releases)

1. Drag and drop `client.dll` into `steamapps\common\Garrysmod\bin`.
2. Restart Garry's Mod
3. Load scripts from your `lua/` directory with `lua_openscript_cl <filename>`.

This isn't guaranteed to work if `client.dll` in this repository has not been updated and patched for a new version of Garry's Mod.

# How It Works

This NOPs the `JNZ` branch called by `lua_openscript_cl` and adds `mov byte ptr [ecx + b8], 1` (x86) or `mov byte ptr [rcx + 168], 1` (x64) aka byte patch `C681B800000001FF 90 84 01 00 00 5E 5D C3` to the end of the function call to escalate lua execution privileges and change where the file loader searches for your script. [For more info see this article.](https://tarasyk.ca/2019/12/14/bypassing-script-enforcer.html)

This patch does NOT modify the `sv_allowcslua` convar whatsoever which can easily be detected by servers, and otherwise is fully undetectable (there are no sigchecks on `client.dll`) + can't get you VAC banned (no VAC on garry's mod).

# Additional tips

To obfuscate your scripts, run this Python3 script which outputs a new script that base64 encodes the script into base64 and then decodes it. Alternatively, you should override `render.capture` which can be used by server admins to take screenshots. 

Check out [Chrollo](https://github.com/qubard/Chrollo) which lets you block anti-cheat scripts among many other things.

```
code = ""
print("Input the path to your script:")
path = input()
with open(path, 'r') as file:
    code = file.read()
    from base64 import b64encode
    code = b64encode(bytes(code, 'utf-8'))
    
final = "local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' \
function dec(data) \
    data = string.gsub(data, '[^'..b..'=]', '') \
    return (data:gsub('.', function(x) \
        if (x == '=') then return '' end \
        local r,f='',(b:find(x)-1) \
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end \
        return r; \
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x) \
        if (#x ~= 8) then return '' end \
        local c=0 \
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end \
            return string.char(c) \
    end)) \
end \
RunString(dec(\"" + code.decode("utf-8") + "\"))"
```
