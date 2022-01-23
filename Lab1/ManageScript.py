import os
import click
import base64
import win32api
import ntsecuritycon as con
import win32security as win32
import win32file
import shutil

def wayoftemplate():
    curpath = os.getcwd()
    return curpath+'\\'+"template.tbl"  # путь к template tbl файлу


# функция для декодирования пароля из файла
def decodepass():
    listoftextfile = []
    way = wayoftemplate()
    mainfile = open(way)
    wayofcurrentfile = os.getcwd()  # получение текущей директории
    for line in mainfile:
        listoftextfile.append(line)
    listoftextfile = [line.rstrip()
                      for line in listoftextfile]  # удаление \n в конце строки
    message = listoftextfile[1]
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64decode(message_bytes)
    base64_message = base64_bytes.decode('ascii')  # дешифрование файла
    return base64_message

# проверка статуса защиты


def checkprotection():
    way = wayoftemplate()
    # получаю информацию о файле
    sd = win32.GetFileSecurity(way, win32.DACL_SECURITY_INFORMATION)
    string = win32.ConvertSecurityDescriptorToStringSecurityDescriptor(
        sd, 1, win32.OWNER_SECURITY_INFORMATION | win32.GROUP_SECURITY_INFORMATION | win32.DACL_SECURITY_INFORMATION)  # конвертирую дескриптор в строку чтобы прочитать
    check = string.find(("(A;"))
    if(check != -1):
        return True
    else:
        return False

# включение защиты


def protectionon():
    way = wayoftemplate()
    everyone = win32.ConvertStringSidToSid(
        'S-1-1-0')  # sid пользователей S-1-1-0
    sd = win32.GetFileSecurity(
        way, win32.DACL_SECURITY_INFORMATION)  # получаю DACL FILENAME
    dacl = win32.ACL()  # инициализация для того чтобы установить новые настройки
    # выставляю правила для userx
    dacl.AddAccessDeniedAce(win32.ACL_REVISION, con.FILE_ALL_ACCESS, everyone)
    # прикрплеяю измененные значения к дескриптору
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    # возвращаю дескриптор
    win32.SetFileSecurity(way, win32.DACL_SECURITY_INFORMATION, sd)

# отключение защиты


def protectionoff():
    way = wayoftemplate()
    everyone = win32.ConvertStringSidToSid(
        'S-1-1-0')  # sid пользователей S-1-1-0
    sd = win32.GetFileSecurity(
        way, win32.DACL_SECURITY_INFORMATION)  # получаю DACL FILENAME
    dacl = win32.ACL()  # инициализация для того чтобы установить новые настройки
    # выставляю правила для userx
    dacl.AddAccessAllowedAce(win32.ACL_REVISION, con.FILE_ALL_ACCESS, everyone)
    # прикрплеяю измененные значения к дескриптору
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    # возвращаю дескриптор
    win32.SetFileSecurity(way, win32.DACL_SECURITY_INFORMATION, sd)

# функция создания файла


def createfile(filename):
    handle = win32file.CreateFile(
        filename, win32file.GENERIC_WRITE, 0, None, win32file.CREATE_NEW, 0, None)
    handle.close()

# функция переименования файла


def renamefile(oldname, newname):
    curpath = os.getcwd()
    oldpath = curpath + '\\' + oldname
    newpath = curpath + '\\' + newname
    win32api.MoveFile(oldpath, newpath)

# функция копии файла


def copyfile(oldpathname, newpath):
    curpath = os.getcwd()
    oldpath = curpath + oldpathname
    shutil.copyfile(oldpathname, newpath)


@click.group()
def cli():
    pass


@cli.command()
@click.option('--key', default=0, help='write key 1/0 for protection/noprotection')
def Edit_status(key):
    """Change protection status"""
    if(key == 1):
        # filepass=decodepass()#возвращает декодированную функцию
        inputpas = input("Password: ")
        if ("password" == inputpas):  # проверка на соотвествие файла
            protectionon()
            click.echo('Protection ON!')
        else:
            click.echo('Incorrect password')
    else:
        protectionoff()
        click.echo('Protection OFF!')


@cli.command()
def Protection_status():
    """Show protection status"""
    check = checkprotection()
    if (check == True):
        click.echo('No protection')
    else:
        click.echo('Protection enabled')


@cli.command()
def CreateFile():
    """Create File"""
    filename = input("Enter name for file: ")
    sep = '.'
    rest = filename.split(sep, 1)[0]
    check = checkprotection()
    if(check == False):
        if (rest == '1234'):
            print("Forbidden name")
        else:
            createfile(filename)
            print("Success")
    else:
        createfile(filename)
        print("Create file success")


@cli.command()
def CopyFile():
    """Copy file"""
    print("Which file do you want copy?")
    curpath = os.getcwd()
    listofile = []
    curpath = os.getcwd()
    listofile = os.listdir(path=curpath)
    for i in listofile:
        print(i)
    fileoldname = input("Enter name: ")
    filenewpath = input("Enter newpath: ")
    sep = '.'
    rest = fileoldname.split(sep, 1)[0]
    check = checkprotection()
    if (check == False):
        if (rest == '1234'):
            print("Forbidden name")
        else:
            copyfile(fileoldname, filenewpath)
            print("Copy file success")
    else:
        copyfile(fileoldname, filenewpath)
        print("Copy file success")


@cli.command()
def RenameFile():
    """Rename file"""
    print("Which file do you want rename?")
    curpath = os.getcwd()
    listofile = []
    curpath = os.getcwd()
    listofile = os.listdir(path=curpath)
    for i in listofile:
        print(i)
    fileoldname = input("Enter name: ")
    filenewname = input("Enter newname: ")
    sep = '.'
    rest = fileoldname.split(sep, 1)[0]
    check = checkprotection()
    if (check == False):
        if (rest == '1234'):
            print("Forbidden name")
        else:
            renamefile(fileoldname, filenewname)
            print("Rename file success")
    else:
        renamefile(fileoldname, filenewname)
        print("Rename file success")


if __name__ == '__main__':
    cli()
