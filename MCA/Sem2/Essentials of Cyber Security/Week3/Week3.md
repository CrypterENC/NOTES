# User & Groups
## Access Control
- **Core Principle:** Linux uses **Discretionary Access Control (DAC)** where the **file owner** decides permissions.
- The 3 Entities: 
	- Read  (r)      -- view
	- Write (w)     -- modify
	- Execute (x)  -- files

- **Permission are set numerically** like `r=4, w=2, x=1`
- Eg: `750` means = `Owner full`, `Group read/execute`, `others got none`.

### The 3 Special Bits:
- **SUID** (runs as file owner, bypasses user permissions).
- **SGID** (new files inherit the directory's group).
- **Sticky Bit** (only the file owner can delete files in that directory).

## Discretionary access control
- DAC is Linux standard permission (read/write/execute) for user/group/other
- DAC means The creator/owner of a file holds the key.
## Users
- Users are fundamental to Linux
- Normally there will be at least two users, the **super user** (root) and the **normal user**.
	- Superuser has total access to do anything within the Linux OS.
	- Normal user can only manipulate his own files and some specific other things.
- When a **user creates a file**, by **default they becomes the owner of the file**.
## Managing Users
### 1. USER CREATION
| Command                                 | What It Does                                            |
| --------------------------------------- | ------------------------------------------------------- |
| `sudo useradd username`                 | Creates user with default settings                      |
| `sudo useradd -m username`              | Creates user **with** home directory (`/home/username`) |
| `sudo useradd -u 1500 username`         | Creates user with **specific UID**                      |
| `sudo useradd -d /custom/home username` | Sets **custom home directory**                          |
| `sudo su <username>`                    | Change to that user.                                    |
### 2. PASSWORD MANAGEMENT
| Command                      | What It Does                                             |     |
| ---------------------------- | -------------------------------------------------------- | --- |
| `sudo passwd username`       | Set or change user password                              |     |
| `sudo passwd -d username`    | Delete password (user can login with **empty** password) |     |
| `sudo passwd -l username`    | **Lock** the account (prefix `!` in `/etc/shadow`)       |     |
| `sudo passwd -u username`    | **Unlock** the account                                   |     |
| `sudo passwd -e username`    | Force password change on **next login**                  |     |
| `sudo passwd -S username`    | Show password **status** (locked, last change, etc.)     |     |
| `sudo passwd -n 7 username`  | Minimum **7 days** before password can be changed        |     |
| `sudo passwd -x 90 username` | Password **expires** after 90 days                       |     |
| `sudo passwd -w 7 username`  | Warn user **7 days** before expiry                       |     |
| `sudo passwd -i 30 username` | Account **inactive** after 30 days of password expiry    |     |
### 3. USER DELETION

| Command                                                           | What It Does                                      |
| ----------------------------------------------------------------- | ------------------------------------------------- |
| `sudo userdel username`                                           | Deletes user account **but keeps** home directory |
| `sudo userdel -r username` or `sudo deluser <name> --remove-home` | Deletes user **and** home directory + mail spool  |
| `sudo userdel -f username`                                        | Force delete (even if user is logged in)          |

## Groups
- Users are grouped together into Groups.
- This allows and owner to manage access to a group of users.
- By default, there will be many users and groups already created for managing your system.
- Use `groups` command to find all the groups a user is a part of.

> **You successfully added `<user>` to the `<group>`, but you're not seeing it in `groups` output. Let me explain why.** **Groups are loaded at login** -- `su - <username>
## Managing Groups
### 1. GROUP MANAGEMENT
| Command                                                                | What It Does                                           |
| ---------------------------------------------------------------------- | ------------------------------------------------------ |
| `sudo groupadd groupname`                                              | Create a new group                                     |
| `sudo groupdel groupname`                                              | Delete group                                           |
| `sudo groupmod -n newname oldname`                                     | Rename group                                           |
| `sudo groupmod -g 2500 groupname`                                      | Change GID                                             |
| `sudo gpasswd -a username groupname`  or `sudo adduser <user> <group>` | Add user to group (**Debian/Ubuntu**)                  |
| `sudo gpasswd -d username groupname`                                   | Remove user from group (**Universal**)                 |
| `sudo deluser username groupname`                                      | Remove user from group (**Debian/Ubuntu** alternative) |

# File Permission

## What does this mean `d rwxrw-r--`
- When we `ls -l` we get this `d rwxrw-r--` these are the permission for the file or dir.
- What does it **indicate**
- A valid permission string has **10 characters**

| Position | Character    | Means                                   |
| -------- | ------------ | --------------------------------------- |
| 1        | `d` (or `-`) | File type (`d` = directory, `-` = file) |
| 2-4      | `rwx`        | Owner permissions                       |
| 5-7      | `rw-`        | Group permissions                       |
| 8-10     | `r--`        | Others permissions                      |
### Types of Permission
- **Read** (**r**)        --> View contents        --> List Contents (ls)
- **Write** (**w**)        --> Modify/delete        --> Create/delete files
- **Execute** (**x**)        --> Run as program        --> Enter directory (cd)

### Changing the File Permission

|Method|Syntax|Example|
|---|---|---|
|**Symbolic**|`chmod u+rwx,g+rx,o-rwx file`|`chmod u+x script.sh`|
|**Numeric (Octal)**|`chmod 755 file`|`chmod 644 file.txt`|
