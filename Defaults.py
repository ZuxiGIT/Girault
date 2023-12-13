Addr = '127.0.0.1'
Port = 65432
Debug = True
LogPath = None


MESSAGE_LENGTH = 1024

ID_LENGTH = 16
ID_PADDING = b'\x00'

MSG_CODE_LENGTH = 4
GET_CLIENT_PUBLIC_KEY = b'\xde\xad\xbe\xef'
GET_PARAMETERS = b'\xbe\xef\xbe\xef'


def pdebug(msg: str) -> None:
    if Debug:
        print(f"[DEBUG] {msg}")
