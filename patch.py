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
                print(hex(bytearr[0]) == hex(int(sig[0], 16)), sig[0] == '?')
                return i
    return None

with open("client.dll", "rb") as f:
    bytes = f.read()
    bytes = bytearray(bytes)
    func_start = sigscan(bytes, sig)
    
    
    if func_start is not None:
        print("Found function! Patching.. at offset " + hex(func_start))
        NOP = int("90", 16)
        bytes[func_start + int("33", 16)] = NOP
        bytes[func_start + int("33", 16) + 1] = NOP
        end = func_start + int("7c", 16)
        patch = ['C6', '81', 'B8', '00', '00', '00', '01', 'FF', '90', '84', '01', '00', '00', '5E', '5D', 'C3']
        patch = [int(b, 16) for b in patch] # convert to hex integers
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

