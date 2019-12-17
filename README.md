# Script-Enforcer-Bypass
A Garry's Mod Script Enforcer bypass that I made which patches `client.dll` to allow `lua_openscript_cl` commands to execute properly. [Get it from the releases page.](https://github.com/qubard/Script-Enforcer-Bypass/releases)

# How It Works

This NOPs the `JNZ` branch at `client.dll + 7cb3` called by `lua_openscript_cl` and adds `mov byte ptr [ecx + b8], 1` aka byte patch `C681B800000001FF 90 84 01 00 00 5E 5D C3` to the end of the function call to escalate lua execution privileges and change where the file loader searches for your script.

This patch does NOT modify the `sv_allowcslua` convar whatsoever which can easily be detected by servers, and otherwise is fully undectable (there are no sigchecks on `client.dll`) + can't get you VAC banned (no VAC on garry's mod).

# Additional tips

To obfuscate your scripts, run this Python3 script which outputs a new script that base64 encodes the script into base64 and then decodes it. Alternatively, you should override `render.capture` which can be used by server admins to take screenshots.

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
