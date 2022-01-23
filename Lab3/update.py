import os
import time
import base64
from secure import set_sys_file
from pathlib import Path
import shutil
import ntsecuritycon as con
import win32security as win32sec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

HOME_DIR = str(Path.home())

# Функция генерации полосы загрузки обновления
def progressBar(iterable, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    total = len(iterable)
    # Функция печати
    def printProgressBar (iteration):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Появление полосы
    printProgressBar(0)
    # Обновление полосы
    for i, item in enumerate(iterable):
        yield item
        printProgressBar(i + 1)
    print()
 
 # Функция сбора информации о системе
def getOsInfo():
    # Узнаю имя пользователя
    sysSpecs = []
    termOutput = os.popen('whoami').read()
    sysSpecs.append("Username: " + termOutput)
    # Узнаю имя хоста
    termOutput = os.popen('hostname').read()
    sysSpecs.append("Host: " + termOutput)
    # Узнаю версию ОС
    termOutput = os.popen('ver').read()
    sysSpecs.append('OS version: ' + termOutput[1:])
    # Узнаю объем памяти
    termOutput = os.popen('wmic MEMORYCHIP get Capacity').read()
    termOutput = termOutput[:42]
    #strTermOut = ''.join(str(termOutput[0]) + ' ' + termOutput[1])
    sysSpecs.append('Total RAM: ' + termOutput)
    # Узнаю модель процессора
    termOutput = os.popen('wmic cpu get name').read()
    termOutput = termOutput[44:]

    sysSpecs.append('Processor: ' + termOutput)
    return sysSpecs

# Генерация пар ключей
def generate_key(path):
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 4096,
        backend = default_backend(),
    )

    # Сохранение приватного ключа в файл
    with open(path + '/private.key', 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Сохранение публичного ключа в файл
    with open(path + '/public.pem', 'wb') as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

# Подпись файла
def sign_file(filePath, fileName):
    file = str(filePath + '/' + fileName)
    # Загрузка приватного ключа
    with open(filePath + '/private.key', 'rb') as key_file: 
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend(),
        )

    # Загрузка подписываемого файла
    with open(file, 'rb') as f:
        payload = f.read()

    # Подпись файла
    signature = base64.b64encode(
        private_key.sign(
            payload,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    )
    with open(filePath + '/signature.sig', 'wb') as f:
        f.write(signature)


print("Make a selection for place folder:\n" +
    "   1. User's home path\n" +
    "   2. Your path")

# Даю выбрать директорию
path = ""
variant = input("Your answer: ")
if (variant == '1'):
    path = HOME_DIR
elif (variant == '2'):
    path = input("Please specify directory you want: ")
else:
    print("Please choose one of the given variants!")
    exit()

directory = "Upgrade" #change
path = os.path.join(path, directory)
print("You will find technical data in " + path)
# Создаю пустую папку, если еще нет
if not os.path.exists(path):
    os.mkdir(path, 0o777)

# Создаю файл sys.tat и заношу в него информацию
sysPath = path + '/sys.tat'
specs = getOsInfo()
if not os.path.exists(sysPath):
    with open(sysPath, 'w', encoding='utf-8') as file:
        for item in specs:
            file.write(item[::-1])

# Произвожу подпись файла
generate_key(path)
sign_file(path, 'sys.tat')

# Вызов эмуляции полосы прогресса
items = list(range(0, 57))
for item in progressBar(items, prefix = 'Progress:', suffix = 'Complete', length = 50):
    time.sleep(0.1)

# Копирую код для защиты
shutil.copy(r'C:\Users\secure.py', r'C:\Users\secure.py') #change
os.system('python secure.py')

# Включаю защиту
#set_sys_file(1)
sd = win32sec.GetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION)
dacl = win32sec.ACL()
sid = win32sec.SID(win32sec.ConvertStringSidToSid("S-1-1-0"))
dacl.AddAccessDeniedAce(win32sec.ACL_REVISION, con.FILE_ALL_ACCESS, sid)
sd.SetSecurityDescriptorDacl(1, dacl, 0)
win32sec.SetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION, sd)



