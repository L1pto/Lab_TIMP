import os
import click
from pathlib import Path
import ntsecuritycon as con
import win32security as win32sec
import base64
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

CURR_DIR = str(Path(__file__).parent.resolve())
SYS_FILE = str(Path(__file__).parent.resolve()) + "/sys.tat"

strogo = 1


# ===CLI functions section===
@click.group()
def cli():
    """
    This program is used to protect file sys.tat from reading without a valid
    signature. If you want to open the file, place .pem and .sig file in this current directory.

    To start using the program run 'python3 secure.py enable/disable'.
    """
    pass


@cli.command(name='disable', help='Disable file protection in current directory')
def disable():
    # Проверка на наличие подписи в директории
    if not os.path.exists(CURR_DIR + '/signature.sig'):
        click.echo("Cannot find signature file!")
        return
    # Проверка на наличие открытого ключа в директории
    if not os.path.exists(CURR_DIR + '/public.pem'):
        click.echo("Cannot find public key file!")
        return

    # Проверка подписи и выключение защиты
    verificate_sign()
    set_sys_file(0)


@cli.command(name='enable', help='Enable file protection in current directory')
def enable():
    # Проверка на наличие подписи в директории
    if not os.path.exists(CURR_DIR + '/signature.sig'):
        click.echo("Cannot find signature file!")
        return
    # Проверка на наличие открытого ключа в директории
    if not os.path.exists(CURR_DIR + '/public.pem'):
        click.echo("Cannot find public key file!")
        return

    # Проверка подписи и выключение защиты
    verificate_sign()
    set_sys_file(1)


# Проверка подписи
def verificate_sign():
    # Загрузка открытого ключа
    if strogo == 0:
        with open(CURR_DIR + '/public.pem', 'rb') as f:
            public_key = load_pem_public_key(f.read(), default_backend())

        # Загрузка подписанного файла и подписи
        with open(SYS_FILE, 'rb') as f:
            payload_contents = f.read()
        with open(CURR_DIR + '/signature.sig', 'rb') as f:
            signature = base64.b64decode(f.read())
    else:
        sd = win32sec.GetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION)
        dacl = win32sec.ACL()
        sid = win32sec.SID(win32sec.ConvertStringSidToSid("S-1-1-0"))
        dacl.AddAccessAllowedAce(win32sec.ACL_REVISION, con.FILE_ALL_ACCESS, sid)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32sec.SetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION, sd)
        with open(CURR_DIR + '/public.pem', 'rb') as f:
            public_key = load_pem_public_key(f.read(), default_backend())

        # Загрузка подписанного файла и подписи
        with open(SYS_FILE, 'rb') as f:
            payload_contents = f.read()
        with open(CURR_DIR + '/signature.sig', 'rb') as f:
            signature = base64.b64decode(f.read())

    # Проверка подписи
    try:
        public_key.verify(
            signature,
            payload_contents,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except cryptography.exceptions.InvalidSignature as e:
        print('ERROR: Проверка подписи файла не пройдена!')
        return


# Включение защиты файла template
def set_sys_file(state):
    # Дополнительная проверка на существование файла
    if os.path.exists(SYS_FILE) == False:
        return

    if state == 1:
        # Устанавливаю права 600 (oct)
        sd = win32sec.GetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION)
        dacl = win32sec.ACL()
        sid = win32sec.SID(win32sec.ConvertStringSidToSid("S-1-1-0"))
        dacl.AddAccessAllowedAce(win32sec.ACL_REVISION, con.FILE_ALL_ACCESS, sid)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32sec.SetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION, sd)
    elif state == 0:
        # Устанавливаю права 644 (oct)
        sd = win32sec.GetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION)
        dacl = win32sec.ACL()
        sid = win32sec.SID(win32sec.ConvertStringSidToSid("S-1-1-0"))
        dacl.AddAccessDeniedAce(win32sec.ACL_REVISION, con.FILE_ALL_ACCESS, sid)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32sec.SetFileSecurity(r'C:\Users\Upgrade\sys.tat', win32sec.DACL_SECURITY_INFORMATION, sd)
        strogo = 1


if __name__ == '__main__':
    cli()