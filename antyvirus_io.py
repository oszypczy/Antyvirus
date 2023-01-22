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
        new_hash = self.calculate_hash(self._file_path)
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

    def calculate_hash(self, path):
        """
        Method that only calculates hash to compare if it was changed
        """
        with open(path, 'rb') as file_holder:
            file_data = file_holder.read()
            new_hash = hashlib.sha256(file_data).hexdigest()
            return new_hash

    def scan_file_for_viruses(self, viruses):
        """
        Methods that scans file and if there is at least one virus,
        changes status of the file to "Dangerous"
        """
        with open(self._file_path, "r") as file_handler:
            file_content = file_handler.read()
            for each_virus in viruses:
                if each_virus in file_content:
                    self.set_file_status("Dangerous")
                    break
                self.set_file_status("Safe")

    def __str__(self):
        """
        Depending on status it is displayed in different colour
        """
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
        self._folder_path = Path(path)
        self._list_of_files = []
        self.download_viruses()

    def download_viruses(self):
        """
        Method that downloads viruses from database
        """
        with open('viruses.txt', 'r') as virus_handle:
            self._viruses = virus_handle.read().splitlines()
        if not self._viruses:
            raise EmptyVirusesFile("The file with viruses is empty.")

    def get_viruses(self):
        return self._viruses

    def get_list_of_files(self):
        return self._list_of_files

    def get_folder_path(self):
        return self._folder_path

    def create_index(self):
        """
        This method is called when when user creates index of files for the first time.
        It appends the list_of_files attribute with every file in the folder
        - Every file added to index has got their status set: Not scanned by deafult
        - It works on the deep level (scans files inside folders which are inside other folders)
        """
        for file in list(self._folder_path.glob('**/*.txt')):
            if os.path.basename(file):
                file_path = os.path.join(self._folder_path, file)
                myfile_object = MyFile(os.path.basename(file), file_path)
                self._list_of_files.append(myfile_object)
                self._list_of_files = sorted(self._list_of_files, key=lambda x: x.get_file_name()) # noqa 551

    def update_index(self):
        """
        This method works when user updates the index of files:
        It appends the list_of_files attibute with only new or edited files.
        - Every file added to index has got their status set: Not scanned by deafult
        - It calls delete_not_existing_files() method to check if any of the already existing
        files was deleted since last update of index and if so deletes it
        """
        list_of_names = [each_file._file_name for each_file in self._list_of_files] # noqa 551
        self.delete_not_existing_files(self._list_of_files, list(self._folder_path.glob('**/*.txt')))
        self.move_files(self._list_of_files, list(self._folder_path.glob('**/*.txt')), list_of_names)
        for file in list(self._folder_path.glob('**/*.txt')):
            if os.path.basename(file) not in list_of_names:
                file_path = os.path.join(self._folder_path, file)
                myfile_object = MyFile(os.path.basename(file), file_path)
                self._list_of_files.append(myfile_object)
                self._list_of_files = sorted(self._list_of_files, key=lambda x: x.get_file_name()) # noqa 551
            else:
                self.check_hash(file)

    def delete_not_existing_files(self, old_list, new_list):
        """
        Method that checks if user deleted any of already existing files
        and if so deletes it from the index
        """
        list_of_names = [file.name for file in new_list]
        for each_file in old_list.copy():
            if each_file.get_file_name() not in list_of_names:
                self._list_of_files.remove(each_file)

    def move_files(self, old_list, new_list, names):
        """
        Method that checks if user moved any of already existing files
        and if so deletes it from the index to create later new instance of this file
        """
        for each_old_file in old_list.copy():
            for each_new_file in new_list:
                if each_old_file.get_file_name() == each_new_file.name:
                    if each_old_file.get_file_path() != each_new_file.as_posix():
                        self._list_of_files.remove(each_old_file)
                        names.remove(each_old_file.get_file_name())

    def check_hash(self, file):
        """
        Method after given file checks file's hash and when
        it is different than previous one, status of the file to: "Not scanned"
        """
        file_path = os.path.join(self._folder_path, file)
        for myfile in self._list_of_files:
            if myfile._file_path == file_path:
                new_hash = myfile.calculate_hash(file_path)
                if myfile._hash != new_hash:
                    myfile.set_file_status("Not scanned")

    def scan_files_for_viruses(self):
        """
        Method that scans files in the folder
        (only files with "Not scanned" status)
        """
        for file in self._list_of_files:
            if file._status == "Not scanned":
                file.scan_file_for_viruses(self._viruses)

    def show_file_info(self):
        files = ''
        for file in self._list_of_files:
            files += (str(file) + '\n')
        return files.rstrip()

    def fix_infected_files(self):
        """
        Method that delete all viruses if file's status is: "Dangerous"
        Changes file's status to safe after fixing
        """
        for file in self._list_of_files:
            if file._status == "Dangerous":
                with open(file._file_path, "r") as f:
                    contents = f.read()
                    for virus in self._viruses:
                        contents = contents.replace(virus, "")
                with open(file._file_path, "w") as f:
                    f.write(contents)
            new_hash = file.calculate_hash(file._file_path)
            file.set_file_hash(new_hash)
            file.set_file_status("Safe")
