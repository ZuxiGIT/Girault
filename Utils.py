import Defaults


def serialize_name(name: str) -> bytes:
    hex_name = name.encode()
    return (Defaults.ID_LENGTH - len(hex_name)) * Defaults.ID_PADDING +\
        hex_name


def deserialize_name(int_bytes: bytes) -> str:
    last_padd = int_bytes.rfind(Defaults.ID_PADDING)
    if last_padd != -1:
        return int_bytes[last_padd+1:].decode('utf-8')
    return int_bytes.decode('utf-8')


def deserialize_name_to_int(int_bytes: bytes) -> int:
    last_padd = int_bytes.rfind(Defaults.ID_PADDING)
    if last_padd != -1:
        return int.from_bytes(int_bytes[last_padd+1:], byteorder='little')
    return int.from_bytes(int_bytes, byteorder='little')


def serialize_integer(secret: int) -> bytes:
    return secret.to_bytes((secret.bit_length() + 7) // 8, byteorder='little')


def deserialize_integer(int_bytes: bytes) -> int:
    return int.from_bytes(int_bytes, byteorder='little')


def name_to_integer(name: str) -> int:
    return int.from_bytes(name.encode(), byteorder='little')
