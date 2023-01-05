import os
import hashlib
from pathlib import Path


class DirectoryNotFound(Exception):
    pass


class InvalidStatusError(Exception):
    pass


class EmptyHashError(Exception):
    pass


class EmptyVirusesFile(Exception):
    pass


class MyFile:

    """
    Class MyFile. Contains file private attributes:
    :file_name: File's name
    :type file_name: str

    :file_path: File's path
    :type file_path: str

    :status: File's status
    :type status: str, deafult = Not scanned

    :hash: File's hash, depends on file's content
    :type hash: str
    """
    def __init__(self, file_name, file_path):
        self._file_name = str(file_name)
        self._file_path = str(file_path)
        self.set_file_status("Not scanned")
        with open(self._file_path, 'rb') as file_holder:
            file_data = file_holder.read()
            new_hash = hashlib.sha256(file_data).hexdigest()
            self.set_file_hash(new_hash)

    def get_file_name(self):
        return self._file_name

    def get_file_path(self):
        return self._file_path

    def get_file_status(self):
        return self._status

    def get_file_hash(self):
        return self._hash

    def set_file_status(self, new_status):
        if new_status not in ('Safe', 'Dangerous', 'Not scanned'):
            raise InvalidStatusError("Status should be either: Safe, Dangerous ot not scanned.") # noqa 551
        self._status = str(new_status)

    def set_file_hash(self, new_hash):
        if not new_hash:
            raise EmptyHashError('Hash of the file cannot be empty.')
        self._hash = str(new_hash)

    """
    Methods that scans file and if there is at least one virus,
    changes status of the file to "Dangerous"
    """
    def scan_file_for_viruses(self, viruses):
        with open(self._file_path, "r") as file_handler:
            file_content = file_handler.read()
            for each_virus in viruses:
                if each_virus in file_content:
                    self.set_file_status("Dangerous")
                    break
                self.set_file_status("Safe")

    """
    Depending on status it is displayed in different colour
    """
    def __str__(self):
        if self._status == "Safe":
            colour = '2'
        elif self._status == "Dangerous":
            colour = '1'
        else:
            colour = '4'
        return f'Name: {self._file_name}, status: \033[3{colour}m{self._status}\033[0m, path: {self._file_path}' # noqa 551


class Folder:
    """
    Class Folder. Contains folder private attributes:
    :path: Folder's path
    :type path: str

    :list_of_files: Folder's list of txt files in it
    :type list_of_files: str
    """
    def __init__(self, path):
        if not os.path.isdir(path):
            raise DirectoryNotFound('Given path is invalid.')
        self._path = Path(path)
        self._list_of_files = []
        self.download_viruses()

    def download_viruses(self):
        with open('viruses.txt', 'r') as virus_handle:
            self._viruses = virus_handle.read().splitlines()
        if not self._viruses:
            raise EmptyVirusesFile("The file with viruses is empty.")

    def get_viruses(self):
        return self._viruses

    def get_list_of_files(self):
        return self._list_of_files

    def get_folder_path(self):
        return self._path

    """
    This method works in 2 different scenarios:
    a) When user creates index of files for the first time:
        - appends the list_of_files attibute with every file in the folder
    b) When user updates the idex of files:
        - appends the list_of_files attibute with only
          new files and when there are files that already
          existed in folder checks their hash looking for edited files
    Every file added to index has got their status set: Not scanned by deafult
    """
    def create_index(self):
        list_of_names = [each_file._file_name for each_file in self._list_of_files] # noqa 551
        path = Path(self._path)
        for file in list(path.glob('**/*.txt')):
            if os.path.basename(file) not in list_of_names:
                file_path = os.path.join(self._path, file)
                txt_file = MyFile(os.path.basename(file), file_path)
                self._list_of_files.append(txt_file)
            else:
                self.check_hash(file)

    """
    Method after given file checks file's hash and when
    it is different than previous one, status of the file to: "Not scanned"
    """
    def check_hash(self, file):
        file_path = os.path.join(self._path, file)
        with open(file_path, 'rb') as file_holder:
            file_data = file_holder.read()
            new_hash = hashlib.sha256(file_data).hexdigest()
        for myfile in self._list_of_files:
            if myfile._file_name == os.path.basename(file) and myfile._hash != new_hash: # noqa 551
                myfile.set_file_status("Not scanned")

    """
    Method that scans files in the folder
    (only files with "Not scanned" status)
    """
    def scan_files_for_viruses(self):
        for file in self._list_of_files:
            if file._status == "Not scanned":
                file.scan_file_for_viruses(self._viruses)

    def show_file_info(self):
        files = ''
        for file in self._list_of_files:
            files += (str(file) + '\n')
        return files.rstrip()

    """
    Method that delete all viruses if file's status is: "Dangerous"
    Changes file's status to safe after fixing
    """
    def fix_infected_files(self):
        for file in self._list_of_files:
            if file._status == "Dangerous":
                with open(file._file_path, "r") as f:
                    contents = f.read()
                    for virus in self._viruses:
                        contents = contents.replace(virus, "")
                with open(file._file_path, "w") as f:
                    f.write(contents)
            with open(file._file_path, 'rb') as file_holder:
                file_data = file_holder.read()
                new_hash = hashlib.sha256(file_data).hexdigest()
                file.set_file_hash(new_hash)
            file.set_file_status("Safe")
