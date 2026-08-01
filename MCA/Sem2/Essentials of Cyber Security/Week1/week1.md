
## Introduction to Linux Terminal
- In the every beginning **MS-DOS and UNIX OS's were fully command line based** because there where no GUI's.
- **Graphical User Interface came much later.**
- **The earlier machines didn't have much resources**, this was one of the reason why terminal was being used.

> The invention of GUI and mouse made computer more accessible

### What is the advantage of the Linux terminal
- Ubiquity:
	- Linux has a lot of GUI interfaces.
		- GNOME
		- KDE
		- PLASMA
	- But the thing is " **MOST OF THE GNU/LINUX use bash and GNU userland tools** ".
- Linux is mainly used as a **SERVER OS**
	- Remote access through terminal is easier and more efficient.
	- This ensures that **everything you can do through the GUI** will be possible through the **CLI**.

### Some Terms
- **Computer Terminal** :  Hardware used to **enter the data and transcribe [ transcribe meaning --> *to convert information from one form into another.  like --> truing audio, video into digital, machine readable text* ] data** from a computer system.
	- Eg: DEC VT 100 [here](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse1.mm.bing.net%2Fth%2Fid%2FOIP.X4CO6fSg5wDwDcsq09ZIAgHaFx%3Fpid%3DApi&f=1&ipt=927809941d5997b5123fa467773ecce3ff5a2539acb048412cc7ce0ea97d12ee&ipo=images)
- **Terminal emulator** : Program that emulates a video terminal.
	- Eg: GNOME Terminal, xterm.
- **Shell** : Program that interprets and executes the user input.
	- Eg: GNU Bash, ZSH, FISH.

### Getting Help in Linux Terminal.
- Terminal interface might seem difficult at first.
- We don't have to memorize each and every commands and its usage right away.
- Linux does comes with excellent documentation for the commands.

1. **Man pages**  `man man  || man 1 ls`
2. **Info pages**   `info ls || info clear`

## Linux File Abstraction
- In Linux ( and Unix), everything is a file.
- But here, "**File**" doesn't just mean a document or a photo. In Linux, a file is abstract **stream of bytes** that the OS can read or write to.
- The thing is that, Linux OS treats almost every resource [Hardware, processes and network connection] as a **file** 

### Types of Files
1. **Regular Files:** Your standard documents, images, and programs.
2. **Directories:** Special files that contain lists of other files
3. **Hardware Devices:** Your mouse, keyboard, and hard drive appear as files in `/dev/` (e.g., `/dev/sda` for your hard drive).
	1. **Process Information:** Running programs appear as files in `/proc/` (e.g., `/proc/cpuinfo` & `/proc/meminfo` & `/proc/pid/fd` ).
4. - **Random Number Generators:** `/dev/random` is a file; reading from it gives you random numbers.
5. **Network Sockets:** Internet connections are represented as files, so you can read incoming network data just by "reading" a file.

> Practical stuff --> perform this "If you want to copy data from your webcam to a video file" --> `cat /dev/video0 > myvideo.mpg`

6. **Discarding data:** we use Null File `/dev/null`

	- What does `/dev/null` actually do?

		- **Reading from it:** If you try to read `/dev/null`, you get **nothing**—it returns an immediate "End of File" (EOF). It's literally empty.
		    
		- **Writing to it:** If you send data to `/dev/null`, the operating system **immediately discards it**. It says "successfully written," pats you on the head, and then instantly deletes that data without saving it anywhere. It never grows in size.

### Viewing a running process and it files in Linux.
1. Get the process id `pid` 
	 - `ps -aux`  get the `pid` of the process, Eg **PID 208**
2. go to proc --> `ls /proc/` look for a folder under that number.
3. go into that folder --> `ls /proc/208` then go into `fd` folder, here FD mean (File Descriptors -- *The `/proc/[PID]/fd/` folder is a **live list of every single file, socket, pipe, and device that a specific running program currently has open.*** )
4. then check where its linking to --> `ls -l /proc/208/fd`
	- you will see a list of symbolic links (shortcuts) named `0`, `1`, `2`, `3`, `4`