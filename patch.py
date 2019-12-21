sig = "55,8b,ec,6a,01,e8,?,?,?,?,83,c4,04,84,c0,74,?,?,?,?,?,?,?,?,74,?,56,8b,75,08,83,3e,02".split(',')

# return the index of the matching signature
def sigscan(bytearr, sig):
    for i in range(0, len(bytearr)):
        if i + len(sig) < len(bytearr):
            found = True
            for j in range(0, len(sig)):
                if sig[j] != '?' and bytearr[i + j] != int(sig[j], 16):
                    found = False
                    break
                    
            if found:
                return i
    return None

with open("client.dll", "rb") as f:
    bytes = f.read()
    bytes = bytearray(bytes)
    func_start = sigscan(bytes, sig)
    
    if func_start is not None:
        print("Found function! Patching.. at offset " + hex(func_start))
        NOP = 0x90
        bytes[func_start + 0x33] = NOP
        bytes[func_start + 0x34] = NOP
        end = func_start + 0x7c
        patch = [0xC6, 0x81, 0xB8, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x90, 0x84, 0x01, 0x00, 0x00, 0x5E, 0x5D, 0xC3]
        for i in range(0, len(patch)):
            bytes[end + i] = patch[i]
        print("Patched..saving to disk")
        import shutil
        print("Backing up client.dll")
        shutil.copyfile("client.dll", "client.dll.bak")
        with open("client.dll", "wb") as f2:
            f2.write(bytes)
    else:
        print("Could not find matching function")
