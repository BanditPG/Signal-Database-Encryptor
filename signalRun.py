import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import subprocess
from getpass import getpass
import ctypes


configFile = "signalRun.json"
signalFile = ""
signalEXE = ""

def ConfigFile():
    global signalEXE
    global signalFile
    global configFile
    
    if(os.path.isfile(configFile)):
        file = open(configFile, 'r', encoding='utf8')
        data = json.load(file)
        file.close()

        signalEXE = data["signalEXE"]
        signalFile = data["signalFile"]
        return True

    else:
        signalEXE = input("signal.exe path: ")
        signalFile = input("Signal config.json: ")

        data = {
            'status':'1',
            'salt':'',
            'signalKey':'',
            'signalEXE' : signalEXE,
            'signalFile' : signalFile
        }

        file = open(configFile, 'w')
        json.dump(data, file)
        file.close()

        return False

def GenerateToken(password, salt):
    password = bytes(password, encoding='utf8')
    if(salt == None):
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    
    return f, salt

def EncodeData(data, token):
    try:
        data = bytes(data, encoding="utf8")
        data = token.encrypt(data)
        return data
    except:
        print("Critical Error")
        return False

def DecryptData(data, token):
    data = token.decrypt(data)
    return data
        
def SignalKeyMenager(key):
    file = open(signalFile, 'r', encoding='utf8')
    signal = json.load(file)
    file.close()

    if(key == None):
        signal["key"] = "It's not that easy"
    else:
        signal["key"] = key

    file = open(signalFile, 'w')
    json.dump(signal, file)
    file.close()

def CreatingPass():
    while True:
        password = getpass("New password: ")
        passwordAgain = getpass("Reapet password: ")
        if(password == passwordAgain):
            break
        os.system("cls")
        
    file = open(signalFile, 'r')
    data = json.load(file)
    file.close()
    token, salt = GenerateToken(password, None)
    data= EncodeData(data['key'], token)
    
    file = open(configFile, 'r')
    config = json.load(file)
    file.close()

    config['signalKey'] = data.decode(encoding='utf8')
    config['salt'] = base64.b64encode(salt).decode(encoding='utf8')
    file = open(configFile, 'w')
    json.dump(config, file)
    file.close()

    SignalKeyMenager(None)

def Login():
    file = open(configFile, 'r')
    config = json.load(file)
    file.close()

    salt = config["salt"]
    salt = base64.b64decode(salt)

    data = config["signalKey"]
    data = bytes(data, encoding='utf8')

    while True:
        try:
            password = getpass("Password: ")
            data = DecryptData(data, GenerateToken(password, salt)[0])
            break
        except:
            print("BAD PASSWORD")

    SignalKeyMenager(data.decode(encoding='utf8'))

def LaunchSignal():
    global signalEXE
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)  
    subprocess.call(signalEXE)

if __name__ == "__main__":
    if(not ConfigFile()):
        CreatingPass()
    Login()
    LaunchSignal()
    SignalKeyMenager(None)