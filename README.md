# Antyvirus 1.0 - Project Description
## Purpose and description of the project:

My project is an antivirus program whose main task is to detect dangerous content in files, inform the user about such files via the interface and remove the threat. The goal, of course, is to increase security when working on a computer. The user can easily control which "viruses" are to be caught through the attached text file, which is a kind of database.

## Program structure:

1. The first and most important file: antivirus_io.py is the file where all the logic of my program is located. It is divided into two classes: file and folder.

    - The MyFile class is a class that stores information about a single text file that has been scanned by the antivirus. The file has its path and name. More importantly, it also has its scan status, which informs the program (and the user in the interface) whether a given file is not yet scanned or whether it has already been scanned and has been marked as safe or dangerous. One of the more interesting attributes is hash, i.e. it is information about whether there have been any changes in the content of the file - it is necessary to later take into account files in which such a change in content was detected during quick scanning.

    - The folder class is a class created on the basis of the only argument in the entire program that is entered by the user, i.e. the path of the folder that he wants to scan. The folder contains a list of file class instances, you can scan it and update its file index. To learn all its methods thoroughly, I invite you to read the documentation already contained directly in the antivirus_io file.

2. The user_interface.py file is a simple but clear interface that allows you to use the antivirus in practice. It does not require any arguments when run through the terminal. So the command: "python3 ./user_interface.py" is enough

    The interface immediately asks the user for the path of the folder he wants to scan (when he gives the wrong one, an appropriate error message will be displayed). It is worth noting that all text files in the entire "tree" of folders will be scanned and listed, which the program will scan under the given path, as long as they have the .txt extension.

    The main menu of the interface is a few simple options for file operations. You can scan files, remove suspicious content, update the index when we know that new files will appear or we have modified existing ones, or you can set a cyclic scan so that the program keeps track of all files and detects threats. It is important for the user to update the index frequently before doing anything else, because then all other file operations will be "visible". If you make wrong selections in the menu, the corresponding errors will also be displayed.

3. The test_antyvirus_io.py test file is a demonstration of the capabilities of the antivirus logic. You can read from it how the program copes with scanning and updating the index. Various io functions, cases and exceptions are tested there. It uses pytest framework.

4. The viruses.txt file is a simple database of "viruses" that the program is supposed to detect in files. The user can add and remove viruses to adjust the antivirus to his own needs. Each new virus must be on a new line in the file.

5. The last file is the "folder" file, which is just an example of a file that the user can scan and perform all the operations possible in the antivirus.

## Instruction:
In order to run the program, you can simply enter the command: "python3 ./user_interface.py" in the terminal.then enter the path to the folder you want to scan and that's it - simple and transparent. After that, it's just a matter of choosing the right options in the menu.

## Reflective part:
I think it is quite a simple and multi-functional program where you can easily make modifications and new options for working with files. It is resistant to exceptions and inappropriate input arguments because it works on the basis of a single user argument - the rest is processed by tested logic. The code is properly divided in accordance with the idea of ​​object-oriented programming, there are no repetitions in it, each method performs its own separate task, but I also tried to include some multi-functional elements to make them work in several scenarios at once, e.g. the folder class method - create_index() during the first scan of the folder successively checks each file, however, during subsequent updates, to save time, I use the "known" file list to update only new and edited (check_hash() method) files. Thanks to this, the program is optimal and faster and works correctly, create_index() creates only an index, but it does it in a different way depending on the scenario (the SOLID principle is fulfilled).