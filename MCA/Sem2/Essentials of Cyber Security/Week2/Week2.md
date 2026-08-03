## Linux Paths 
- Path is simply the **address** of a file on your system.
- It tells the Linux kernel exactly where to find something within the single, unified directory tree that starts at the root `(/)`
### Creating Paths
#### Absolute Paths
 - The exact, full address from the top of the system.
#### Relative Paths
 - The address relative to where you are right now in the terminal.

![[abs&relative_path.png]]

**AP :**
- `/var/lib`
**RP :**
		- `../var/lib`

## Shell: Essential Concepts
1. Stop a Process : `contrl + z`
2. Resume a Process : `fg`
3. Move the Process to background : `bg`
4. Display all running current processes : `ps` || `ps -e`

## Shell: Input/Output
### The Big 3: Standard Input, Output, and Error
| Door Number | Name                | Symbol   | What it does                                     | Default location      |
| ----------- | ------------------- | -------- | ------------------------------------------------ | --------------------- |
| **0**       | **Standard Input**  | `stdin`  | Where the program **reads** its input from.      | Your keyboard.        |
| **1**       | **Standard Output** | `stdout` | Where the program **writes** its normal results. | Your terminal screen. |
| **2**       | **Standard Error**  | `stderr` | Where the program **writes** its error messages. | Your terminal screen  |
### I/O Redirection
Since we know what file descriptors that programs are using, we can manipulate them.
1. `<` --> Input Redirect
2. `>` --> Output Redirect
3. `>>` --> Append Redirect
4. `2>` --> Error Redirect
5. `| (pipe)` --> Pipeline

> `cat /dev/urandom 1>&2 2>/dev/null` if urandom is not present in system then **move to dev/null** but if its there then display it.

## File Manipulation
### 1. File Creation
1. Creating an Empty File: `touch`  || `touch myfile.txt` || `touch file1.txt file2.txt file3.txt`
2. Creating a File with Content: > and >> (Redirection) 
```bash
echo "Hello World" > myfile.txt   # Creates file with "Hello World"
echo "Second line" >> myfile.txt  # Adds "Second line" to the end
```

### 2. Special File Creation
1. Creating Directories: `mkdir`
```bash
mkdir myfolder          # Creates a single folder
mkdir -p parent/child   # Creates parent AND child folders in one go
```
2. Creating Symbolic Links (Shortcuts): `ln -s` || `ln -s /original/file.txt /shortcut/link.txt`
3. `mkfifo` -- **Create Named Pipes** (FIFOs)
```markdown
- it is a temp tunnel between programs:
  - **Process A** writes data into the pipe.
  - **Process B** reads data from the pipe.
    
- The data flows in one direction, like water through a pipe.
  
- Create a Named Pipe
`mkfifo pipe_name`

`echo "Hello through the pipe" > pipe_name`  #type this in terminal 1
`cat < pipe_name`                            #type this in terminal 2
```
4. `mknod` -- **Create Device Files** 
- **Device files** are how Linux talks to hardware. Remember "everything is a file"? This is where that comes to life!

- There are **two types** of device files:

| Type                 | What it does                                                | Example                                    |
| -------------------- | ----------------------------------------------------------- | ------------------------------------------ |
| **Character Device** | Transfers data one **character at a time** (like a stream). | Keyboard, mouse, serial ports (`/dev/tty`) |
| **Block Device**     | Transfers data in **blocks** (chunks) with random access.   | Hard drives, USB drives (`/dev/sda`)       |
### The Syntax

```bash
mknod <name> <type> <major> <minor>

- **`<name>`**: The filename you want to create.  
- **`<type>`**: `c` for character, `b` for block. 
- **`<major>`**: The driver number (which driver handles this device).
- **`<minor>`**: The specific device number (which instance of that driver).
```

```bash
sudo mknod /dev/mydevice c 4 1       # Example: Creating a Character Device
sudo mknod /dev/myharddrive b 8 2    ### Example: Creating a Block Device
```

### 3. Moving Files
#### Renaming 
```bash
mv oldname.txt newname.txt
```
#### Move a file to a different folder
```bash
mv myfile.txt /home/alice/Documents/
```
#### Move a folder (and everything inside it) 
```bash
mv myfolder /home/alice/Backup/
```

> **Warning:** If the destination already has a file with the same name, `mv` will **overwrite it without asking!** To be safe, use `-i` (interactive) to ask for confirmation:

### 4. Deleting Files
> **WARNING:** In Linux, `rm` **permanently deletes** files. There is NO Recycle Bin. Once deleted, they are gone forever!

#### Delete a single file
```bash
rm myfile.txt
```
#### Delete multiple files
```bash
rm file1.txt file2.txt file3.txt
```
#### Delete interactively (asks before each deletion)
```bash
rm -i myfile.txt
```
#### Force delete (ignore warnings)
```bash
rm -f myfile.txt
```
####  Deleting Directories: `rmdir` and `rm -r`
```bash
rmdir myfolder
```
#### Delete a directory **and everything inside it** (recursive)
```bash
rm -r myfolder
```
#### Basic Regular Expression
Regular expressions are **search patterns** used to find text. You use them with commands like `grep`, `sed`, and `awk`.

Here are the **absolute basics** you need to know:

| Pattern   | What it matches                        | Example                                          |
| --------- | -------------------------------------- | ------------------------------------------------ |
| `.` (dot) | Any **single** character               | `h.t` matches "hat", "hot", "h1t"                |
| `*`       | Zero or more of the previous character | `ho*` matches "h", "ho", "hoo", "hooo"           |
| `^`       | Start of a line                        | `^Hello` matches lines starting with "Hello"     |
| `$`       | End of a line                          | `world$` matches lines ending with "world"       |
| `[abc]`   | Any ONE character from the set         | `[aeiou]` matches any vowel                      |
| `[a-z]`   | Any ONE character in a range           | `[A-Z]` matches any capital letter               |
| `\`       | Escape special characters              | `\.` matches a literal dot (not "any character") |
### Searching
#### Search inside files 
```bash
grep "word" *.txt

grep -r "error" /var/log  # Search RECURSIVELY (in all subfolders) for "error"
grep -i "hello" file.txt  # Case-insensitive search (matches Hello, HELLO, etc.)
```
#### Search for files : `find`
```bash
find . -name "myfile.txt"        # Search current folder for a file by name
find / -name "*.pdf"             # Search the whole system for all PDFs
find . -type d                   # Find all directories (folders)
find . -type f -size +100M       # Find all files larger than 100MB
```
#### Searching FOR files (faster): `locate`
```bash
locate myfile.txt   # Instantly finds any file with "myfile.txt" in its name
sudo updatedb       # Update the database (if you just created a file)
```