import sys
import os
import struct
import brotli

TAURI_APP_PATH = ''
TAURI_APP_BASE_ADDRESS = 0
TAURI_APP_RDATA_OFFSET = 0
TAURI_APP_CONTENT = b''
RESOURCE_TABLE_BEGIN_ADDRESS = 0
RESOURCE_TABLE_END_ADDRESS = 0

def p64(value: int) -> bytes:
    return struct.pack('<Q', value)

def u64(value: bytes) -> int:
    return struct.unpack('<Q', value)[0]

def p32(value: int) -> bytes:
    return struct.pack('<I', value)

def u32(value: bytes) -> int:
    return struct.unpack('<I', value)[0]

def address_to_offset(address: int) -> int:
    return address - TAURI_APP_RDATA_OFFSET

def offset_to_address(offset: int) -> int:
    return offset + TAURI_APP_RDATA_OFFSET

def deref_ptr(address: int, length: int) -> bytes:
    offset = address_to_offset(address)
    return TAURI_APP_CONTENT[offset:offset+length]

def deref_offset(offset: int, length: int) -> bytes:
    return TAURI_APP_CONTENT[offset:offset+length]

deref_as_qword = lambda addr: deref_ptr(addr, 8)
deref_as_dword = lambda addr: deref_ptr(addr, 4)
deref_as_word = lambda addr: deref_ptr(addr, 2)
deref_as_byte = lambda addr: deref_ptr(addr, 1)
deref_offset_as_qword = lambda offset: deref_offset(offset, 8)
deref_offset_as_dword = lambda offset: deref_offset(offset, 4)
deref_offset_as_word = lambda offset: deref_offset(offset, 2)
deref_offset_as_byte = lambda offset: deref_offset(offset, 1)

def parse_path(path: str) -> list[str]:
    return list(filter(lambda x: x != '' or x != '.', path.split('/')))

def try_decompress_brotli(value: bytes) -> bytes | None:
    while True:
        try:
            if len(value) == 0:
                break
            return brotli.decompress(value)
        except:
            value = value[:-1]
    return None

def check_is_tauri_app() -> bool:
    return b"GetAppVersionGetAppNameGetTauriVersion" in TAURI_APP_CONTENT

def find_tauri_app_base():
    global TAURI_APP_BASE_ADDRESS, TAURI_APP_RDATA_OFFSET, RESOURCE_TABLE_BEGIN_ADDRESS, RESOURCE_TABLE_END_ADDRESS
    if TAURI_APP_CONTENT[:2] == b'\x4d\x5a':
        # PE file
        pe_offset = u32(TAURI_APP_CONTENT[0x3c:0x40])
        if TAURI_APP_CONTENT[pe_offset:pe_offset+4] == b'PE\x00\x00':
            base_addr_start = pe_offset + 0x30
            text_base_addr = (u64(TAURI_APP_CONTENT[base_addr_start:base_addr_start+8]) >> 12 << 12) + 0x1000
        else:
            print("Invalid PE file.")
            sys.exit(1)

        TAURI_APP_BASE_ADDRESS = text_base_addr

    else:
        print("Not a PE file.")
        sys.exit(1)

    # find last tauri app static resource
    offset = TAURI_APP_CONTENT.find(b'\x27sha256')
    if offset == -1:
        print("No resource found.")
        sys.exit(1)
    i = 8
    while True:
        qword = u64(deref_offset_as_qword(offset + i))
        i += 8
        if (qword >> 24) == (TAURI_APP_BASE_ADDRESS >> 24):
            break

    TAURI_APP_RDATA_OFFSET = qword - offset
    
    match try_get_table_address(offset):
        case None:
            print("No resource table found.")
            sys.exit(1)
        case (addr, length):
            # the resource table is next to the last resource
            RESOURCE_TABLE_BEGIN_ADDRESS = addr + length
            if RESOURCE_TABLE_BEGIN_ADDRESS % 8 != 0:
                RESOURCE_TABLE_BEGIN_ADDRESS += 8 - RESOURCE_TABLE_BEGIN_ADDRESS % 8
            RESOURCE_TABLE_END_ADDRESS = offset_to_address(offset)

    if RESOURCE_TABLE_BEGIN_ADDRESS == 0 or RESOURCE_TABLE_END_ADDRESS == 0:
        print("invalid resource table address.")
        sys.exit(1)

    assert (RESOURCE_TABLE_END_ADDRESS - RESOURCE_TABLE_BEGIN_ADDRESS) % 0x20 == 0, "Invalid resource table size."
    

def try_get_table_address(offset: int) -> tuple[int, int] | None:
    last_data_length = TAURI_APP_CONTENT[offset-8:offset]
    last_data_ptr = TAURI_APP_CONTENT[offset-0x10:offset-8]
    last_data_length = u64(last_data_length)
    last_data_ptr = u64(last_data_ptr)

    if last_data_length == 0 or last_data_ptr == 0:
        return None
    
    last_data = deref_as_byte(last_data_ptr)
    
    # check if brotli compressed
    if last_data != b'\x1b':
        return None
    
    return (last_data_ptr, last_data_length)

def parse_tauri_app_resources():
    root_dir = parse_path(TAURI_APP_PATH).pop().split('.')[0] + '_resources'
    if not os.path.exists(root_dir):
        os.makedirs(root_dir)
    else:
        print(f"Directory {root_dir} already exists.")
        print("Do you want to extract the resources to this directory? (y/N)")
        if input().lower() != 'y':
            sys.exit(0)
    os.chdir(root_dir)

    print("Extracting resources...")
    resource_count = 0
    success_count = 0

    for addr in range(
        RESOURCE_TABLE_BEGIN_ADDRESS, 
        RESOURCE_TABLE_END_ADDRESS, 
        0x20
    ):
        name_ptr = u64(deref_as_qword(addr))
        name_length = u64(deref_as_qword(addr+8))
        data_ptr = u64(deref_as_qword(addr+0x10))
        data_length = u64(deref_as_qword(addr+0x18))
        if name_ptr == 0 or name_length == 0 or data_ptr == 0 or data_length == 0:
            continue
        try:
            name = deref_ptr(name_ptr, name_length).decode('utf-8')
            if name.startswith("/"):
                name = name[1:]
            print(f"[*] Find \"{name}\"")
            resource_count += 1
            data = deref_ptr(data_ptr, data_length)
            data = try_decompress_brotli(data)
            if data is None:
                print(f"Failed to decompress {name}.")
                continue
            # create dirs if name contains path
            path = parse_path(name)
            if len(path) > 1:
                os.makedirs('/'.join(path[:-1]), exist_ok=True)

            with open(name, 'wb') as f:
                f.write(data)
            print(f"[+] Stored in {root_dir}/{name}.")
            success_count += 1
        except:
            print(f"Error: Failed to extract {name}.")
            continue
    print("Extraction complete.")
    print(f"Found {resource_count} resources, extracted {success_count} resources, {resource_count - success_count} failed.")

class TauriReader:
    def __init__(self, path: str):
        self.path = path

    def extract(self):
        global TAURI_APP_PATH, TAURI_APP_CONTENT

        # Check if the path exists
        if not os.path.exists(self.path):
            print(f"Path {self.path} does not exist.")
            sys.exit(1)

        TAURI_APP_PATH = self.path

        # Check if the path is a binary
        if os.path.isdir(self.path):
            print("Expected binary file, found directory.")
            sys.exit(1)

        # Get absolute path
        self.path = os.path.abspath(self.path)

        # Read the tauri app
        with open(self.path, 'rb') as app:
            TAURI_APP_CONTENT = app.read()

        # Check if the app is a tauri app
        if not check_is_tauri_app():
            print(f"The file {self.path} may not be a tauri app.")
            sys.exit(1)

        find_tauri_app_base()            
        
        # Parse the tauri app and extract the resources
        parse_tauri_app_resources()