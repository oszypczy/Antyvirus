from antyvirus_io import Folder, DirectoryNotFound
import os
from time import sleep


class IncorrectInputData(Exception):
    pass


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    cls()
    folder_path = input("Give directory path which you want to scan: ")
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise DirectoryNotFound('Given directory is invalid.')
    else:
        cls()
        folder = Folder(folder_path)
        folder.create_index()
        folder.scan_files_for_viruses()
        print(folder.show_file_info())
        while True:
            print()
            print("Antyvirus options:")
            print("1. Fix infected files")
            print("2. Execute fast scan")
            print("3. Set cycle scan")
            print("4. Update index of files")
            print("5. End the programme")
            choice = input("Choose an option (enter a number between 1-5): ")
            if choice == "1":
                cls()
                folder.fix_infected_files()
                print(folder.show_file_info())
            elif choice == '2':
                cls()
                folder.update_index()
                folder.scan_files_for_viruses()
                print(folder.show_file_info())
            elif choice == '3':
                seconds = input("What sould be the period between scans (seconds): ") # noqa 551
                while True:
                    cls()
                    folder.update_index()
                    folder.scan_files_for_viruses()
                    print(folder.show_file_info())
                    sleep(int(seconds))
            elif choice == '4':
                cls()
                folder.update_index()
                print(folder.show_file_info())
            elif choice == '5':
                break
            else:
                raise IncorrectInputData('You should enter number between 1-5')


if __name__ == "__main__":
    main()
