sigpe = "50,45,00,00".split(',')
sig86 = "55,8b,ec,6a,01,e8,?,?,?,?,83,c4,04,84,c0,74,?,?,?,?,?,?,?,?,74,?,56,8b,75,08,83,3e,02".split(',')
sig64 = "40,53,48,83,ec,30,48,8b,d9,b1,01,e8,?,?,?,?,84,c0,0f,?,?,?,?,?,?,?,?,?,?,?,?,?,0f,?,?,?,?,?,?,?,?,7c,?,e8".split(',')
NOP = 0x90


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


def is_64(input_bytes: bytearray) -> bool:
    pe_start = sigscan(input_bytes, sigpe)
    return input_bytes[pe_start + 0x4] == 0x64


def patch_86(input_bytes: bytearray) -> bool:
    func_start = sigscan(input_bytes, sig86)

    if func_start is not None:
        print("Found function! Patching.. at offset " + hex(func_start))

        input_bytes[func_start + 0x33] = NOP
        input_bytes[func_start + 0x34] = NOP
        end = func_start + 0x7c
        patch = [0xC6, 0x81, 0xB8, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x90, 0x84, 0x01, 0x00, 0x00, 0x5E, 0x5D, 0xC3]
        for i in range(0, len(patch)):
            input_bytes[end + i] = patch[i]

        return True

    return False


def patch_64(input_bytes: bytearray) -> bool:
    func_start = sigscan(input_bytes, sig64)

    if func_start is not None:
        print("Found function! Patching.. at offset " + hex(func_start))

        input_bytes[func_start + 0x3B] = NOP
        input_bytes[func_start + 0x3C] = NOP
        end = func_start + 0x78
        patch = [0xC6, 0x81, 0x68, 0x01, 0x00, 0x00, 0x01]

        for i in range(0, 0x2F + 0x1):
            patch.append(input_bytes[end + 0x5 + i])

        for i in range(0, len(patch)):
            input_bytes[end + i] = patch[i]

        return True

    return False


with open("client.dll", "rb") as f:
    file_bytes = f.read()
    file_bytes = bytearray(file_bytes)

    success = False

    if is_64(file_bytes):
        print("Detected x64 executeable...")
        success = patch_64(file_bytes)
    else:
        print("Detected x86 executeable...")
        success = patch_86(file_bytes)

    if success:
        print("Patched..saving to disk")

        import shutil

        print("Backing up client.dll")
        shutil.copyfile("client.dll", "client.dll.bak")

        with open("client.dll", "wb") as f2:
            f2.write(file_bytes)
    else:
        print("Could not find matching function")
