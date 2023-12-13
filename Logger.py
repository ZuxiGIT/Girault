'''
class Colors:
    Reset = '\033[0m'
    Bold = '\033[01m'
    Disable = '\033[02m'
    Underline = '\033[04m'
    Reverse = '\033[07m'
    Strikethrough = '\033[09m'
    Invisible = '\033[08m'

    class FG:
        Black = '\033[30m'
        Red = '\033[31m'
        Green = '\033[32m'
        Orange = '\033[33m'
        Blue = '\033[34m'
        Purple = '\033[35m'
        Cyan = '\033[36m'
        Lightgrey = '\033[37m'
        Darkgrey = '\033[90m'
        Lightred = '\033[91m'
        Lightgreen = '\033[92m'
        Yellow = '\033[93m'
        Lightblue = '\033[94m'
        Pink = '\033[95m'
        Lightcyan = '\033[96m'

    class BG:
        Black = '\033[40m'
        Red = '\033[41m'
        Green = '\033[42m'
        Orange = '\033[43m'
        Blue = '\033[44m'
        Purple = '\033[45m'
        Cyan = '\033[46m'
        Lightgrey = '\033[47m'
'''

from datetime import datetime


class Logger:
    def __init__(self, filepath: str = None):
        self.file = open(filepath, "a") if filepath is not None else None

    def log(self, msg: str):
        res = datetime.now().strftime("[%Y.%m.%d %H:%M:%S.%f]")
        res += msg
        if self.file is not None:
            self.file.write(res)
        else:
            print(res)

    def info(self, msg: str) -> None:
        self.log(f"[INFO] {msg}")

    def warn(self, msg: str) -> None:
        self.log(f"[WARN] {msg}")

    def error(self, msg: str) -> None:
        self.log(f"[ERRO] {msg}")
