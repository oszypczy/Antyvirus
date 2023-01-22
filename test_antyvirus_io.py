from antyvirus_io import (
    MyFile,
    Folder,
    DirectoryNotFound,
    InvalidStatusError,
    EmptyHashError,
    EmptyVirusesFile
)
from pytest import raises
import os
import shutil
from pathlib import Path
from io import StringIO


def test_create_file_invalid_path():
    with raises(FileNotFoundError):
        MyFile('file1.txt', '/home/file999.txt')


def test_create_file_invalid_name():
    with raises(FileNotFoundError):
        MyFile('AAA', '/home/file1.txt')


def test_create_file_empty_name():
    with raises(FileNotFoundError):
        MyFile('', '/home/file999.txt')


def test_create_file_empty_path():
    with raises(FileNotFoundError):
        MyFile('file1.txt', '')


def test_download_viruses():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    folder.download_viruses()
    assert folder._viruses == [
        "X5O!P%@AP[4/PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "X5O!P%AIUSDHWTA&%#*@(HD(A*H$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "AUDIGW*GD*ASYDWQSDAD*DIA^$#@EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ]
    shutil.rmtree(folder_path)


def test_download_viruses_empty_virus_file(monkeypatch):
    def mock_open(name, mode):
        return StringIO()
    monkeypatch.setattr("builtins.open", mock_open)
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    with raises(EmptyVirusesFile):
        Folder(folder_path)
    shutil.rmtree(folder_path)


def test_set_file_status():
    with open('file70.txt', 'w') as file_handler:
        file_handler.write('70')
    file_path = os.path.abspath('file70.txt')
    file1 = MyFile('file70.txt', file_path)
    assert file1.get_file_status() == 'Not scanned'
    file1.set_file_status("Safe")
    assert file1.get_file_status() == 'Safe'
    os.remove(file_path)


def test_set_file_status_invalid():
    with open('file70.txt', 'w') as file_handler:
        file_handler.write('70')
    file_path = os.path.abspath('file70.txt')
    file1 = MyFile('file70.txt', file_path)
    assert file1.get_file_status() == 'Not scanned'
    with raises(InvalidStatusError):
        file1.set_file_status("New")
    os.remove(file_path)


def test_set_file_hash():
    with open('file70.txt', 'w') as file_handler:
        file_handler.write('70')
    file_path = os.path.abspath('file70.txt')
    file1 = MyFile('file70.txt', file_path)
    assert file1.get_file_hash() == 'ff5a1ae012afa5d4c889c50ad427aaf545d31a4fac04ffc1c4d03d403ba4250a' # noqa 551
    file1.set_file_hash("aowhdohaw0ye9qupjdpoauw0ud0q31739yeoqh83e")
    assert file1.get_file_hash() == "aowhdohaw0ye9qupjdpoauw0ud0q31739yeoqh83e"
    os.remove(file_path)


def test_set_file_hash_invalid():
    with open('file70.txt', 'w') as file_handler:
        file_handler.write('70')
    file_path = os.path.abspath('file70.txt')
    file1 = MyFile('file70.txt', file_path)
    with raises(EmptyHashError):
        file1.set_file_hash("")
    os.remove(file_path)


def test_create_file_typical():
    with open('file70.txt', 'w') as file_handler:
        file_handler.write('70')
    file_path = os.path.abspath('file70.txt')
    file1 = MyFile('file70.txt', file_path)
    assert file1.get_file_name() == 'file70.txt'
    assert file1.get_file_path() == file_path
    assert file1.get_file_status() == 'Not scanned'
    assert file1.get_file_hash() == 'ff5a1ae012afa5d4c889c50ad427aaf545d31a4fac04ffc1c4d03d403ba4250a' # noqa 551
    assert str(file1) == f'Name: file70.txt, status: \x1b[34mNot scanned\x1b[0m, path: {file_path}' # noqa 551
    os.remove(file_path)


def test_create_folder_typical():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    assert folder.get_folder_path() == Path(folder_path)
    assert folder.get_list_of_files() == []
    shutil.rmtree(folder_path)


def test_create_folder_invalid_path():
    with raises(DirectoryNotFound):
        Folder('aiuwdhiuawhd')


def test_create_index():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    with open(os.path.join(folder_path, "file1.txt"), "w") as f:
        f.write("It is file1.txt file\n")
        f.write("It is safe")
    with open(os.path.join(folder_path, "file2.txt"), "w") as f:
        f.write("It is file2.txt file\n")
        f.write('It is dangerous\n')
        f.write("AUDIGW*GD*ASYDWQSDAD*DIA^$#@EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") # noqa 551
    folder.create_index()
    assert len(folder.get_list_of_files()) == 2
    list_of_names = [each_file.get_file_name() for each_file in folder.get_list_of_files()] # noqa 551
    assert list_of_names == ['file1.txt', 'file2.txt']
    shutil.rmtree(folder_path)


def test_scan_file_for_viruses():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    with open(os.path.join(folder_path, "file1.txt"), "w") as f:
        f.write("It is file1.txt file\n")
        f.write("It is safe")
    with open(os.path.join(folder_path, "file2.txt"), "w") as f:
        f.write("It is file2.txt file\n")
        f.write('It is dangerous\n')
        f.write("AUDIGW*GD*ASYDWQSDAD*DIA^$#@EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") # noqa 551
    folder.create_index()
    folder.scan_files_for_viruses()
    assert folder.get_list_of_files()[0].get_file_status() == 'Safe'
    assert folder.get_list_of_files()[1].get_file_status() == 'Dangerous'
    shutil.rmtree(folder_path)


def test_check_hash_file_edited():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    with open(os.path.join(folder_path, "file1.txt"), "w") as f:
        f.write("It is file1.txt file\n")
        f.write("It is safe")
    folder.create_index()
    assert folder.get_list_of_files()[0].get_file_status() == 'Not scanned'
    folder.scan_files_for_viruses()
    assert folder.get_list_of_files()[0].get_file_status() == 'Safe'
    with open(os.path.join(folder_path, "file1.txt"), "w") as f:
        f.write("It is file1.txt file\n")
        f.write("It is edited\n")
        f.write("It is not safe anymore")
    folder.check_hash("file1.txt")
    assert folder.get_list_of_files()[0].get_file_status() == 'Not scanned'
    shutil.rmtree(folder_path)


def test_check_hash_file_not_edited():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    with open(os.path.join(folder_path, "file1.txt"), "w") as f:
        f.write("It is file1.txt file\n")
        f.write("It is safe")
    folder.create_index()
    assert folder.get_list_of_files()[0].get_file_status() == 'Not scanned'
    folder.scan_files_for_viruses()
    assert folder.get_list_of_files()[0].get_file_status() == 'Safe'
    folder.check_hash("file1.txt")
    assert folder.get_list_of_files()[0].get_file_status() == 'Safe'
    shutil.rmtree(folder_path)


def test_fix_infected_files():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    with open(os.path.join(folder_path, "file1.txt"), "w") as f:
        f.write("It is file1.txt file\n")
        f.write('After fixing virus will be deleted\n')
        f.write("AUDIGW*GD*ASYDWQSDAD*DIA^$#@EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") # noqa 551
    folder.create_index()
    folder.scan_files_for_viruses()
    assert folder.get_list_of_files()[0].get_file_status() == 'Dangerous'
    folder.fix_infected_files()
    with open(os.path.join(folder_path, "file1.txt"), "r") as f:
        content = f.read()
    assert content == 'It is file1.txt file\nAfter fixing virus will be deleted\n' # noqa 551
    assert folder.get_list_of_files()[0].get_file_status() == 'Safe'
    shutil.rmtree(folder_path)


def test_deleting_files_from_index():
    current_dir = os.getcwd()
    folder_path = os.path.join(current_dir, "test_folder")
    os.mkdir(folder_path)
    folder = Folder(folder_path)
    with open(os.path.join(folder_path, "file1.txt"), "w") as f:
        f.write("It is file1.txt file\n")
        f.write("It is safe")
    with open(os.path.join(folder_path, "file2.txt"), "w") as f:
        f.write("It is file2.txt file\n")
        f.write('It is dangerous\n')
        f.write("AUDIGW*GD*ASYDWQSDAD*DIA^$#@EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") # noqa 551
    folder.create_index()
    assert len(folder.get_list_of_files()) == 2
    list_of_names = [each_file.get_file_name() for each_file in folder.get_list_of_files()] # noqa 551
    assert list_of_names == ['file1.txt', 'file2.txt']
    os.remove(os.path.join(folder_path, "file2.txt"))
    folder.update_index()
    assert len(folder.get_list_of_files()) == 1
    list_of_names = [each_file.get_file_name() for each_file in folder.get_list_of_files()] # noqa 551
    assert list_of_names == ['file1.txt']
    shutil.rmtree(folder_path)
