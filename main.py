from App import *

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


if __name__ == '__main__':
    root = tk.Tk()
    app = Application(root)
    root.mainloop()