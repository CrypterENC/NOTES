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

|Command|What It Does|
|---|---|
|`sudo adduser username`|Creates user with **home dir**, **shell**, **password** (interactive)|
|`sudo adduser --system username`|Creates **system user** (no home, no login)|
|`sudo adduser --home /custom/dir username`|Creates user with **custom home directory**|
|`sudo adduser --shell /bin/zsh username`|Creates user with **specific shell**|
|`sudo adduser --uid 1500 username`|Creates user with **specific UID**|
|`sudo useradd -m username`|Low-level alternative (no prompts, no password)|

### 2. PASSWORD MANAGEMENT

|Command|What It Does|
|---|---|
|`sudo passwd username`|Set or change user password|
|`sudo passwd -d username`|Delete password (empty password – **insecure**)|
|`sudo passwd -l username`|**Lock** the account|
|`sudo passwd -u username`|**Unlock** the account|
|`sudo passwd -e username`|Force password change on **next login**|
|`sudo passwd -S username`|Show password **status**|
|`sudo passwd -n 7 username`|Minimum **7 days** before password change|
|`sudo passwd -x 90 username`|Password **expires** after 90 days|
|`sudo passwd -w 7 username`|Warn user **7 days** before expiry|
|`sudo passwd -i 30 username`|Account **inactive** after 30 days|

### 3. USER DELETION (Debian/Ubuntu)

|Command|What It Does|
|---|---|
|`sudo deluser username`|Deletes user **but keeps** home directory|
|`sudo deluser --remove-home username`|Deletes user **and** home directory|
|`sudo deluser --remove-all-files username`|Deletes user + home + mail spool + all files owned by user|
|`sudo deluser --backup username`|Backs up home directory before deletion|
|`sudo userdel -r username`|Alternative (lower-level) – deletes user + home|

### 4. USER MODIFICATION (Debian/Ubuntu)

| Command                               | What It Does                |
| ------------------------------------- | --------------------------- |
| `sudo usermod -l newname oldname`     | Change **username**         |
| `sudo usermod -d /new/home username`  | Change **home directory**   |
| `sudo usermod -s /bin/zsh username`   | Change **login shell**      |
| `sudo usermod -u 2000 username`       | Change **UID**              |
| `sudo usermod -g groupname username`  | Change **primary group**    |
| `sudo usermod -L username`            | Lock account                |
| `sudo usermod -U username`            | Unlock account              |
| `sudo usermod -e 2025-12-31 username` | Set **account expiry date** |

## Groups
- Users are grouped together into Groups.
- This allows and owner to manage access to a group of users.
- By default, there will be many users and groups already created for managing your system.
- Use `groups` command to find all the groups a user is a part of.

> **You successfully added `<user>` to the `<group>`, but you're not seeing it in `groups` output. Let me explain why.** **Groups are loaded at login** -- `su - <username>
## Managing Groups
### 1. GROUP CREATION & DELETION

| Command                            | What It Does                                |
| ---------------------------------- | ------------------------------------------- |
| `sudo addgroup groupname`          | Create a new group (Debian/Ubuntu friendly) |
| `sudo groupadd groupname`          | Create a new group (low-level)              |
| `sudo delgroup groupname`          | Delete group (Debian/Ubuntu friendly)       |
| `sudo groupdel groupname`          | Delete group (low-level)                    |
| `sudo groupmod -n newname oldname` | Rename group                                |
| `sudo groupmod -g 2500 groupname`  | Change GID                                  |

### 2. ADD/REMOVE USERS TO/FROM GROUPS (Debian/Ubuntu)

|Command|What It Does|
|---|---|
|`sudo adduser username groupname`|Add user to **secondary group**|
|`sudo deluser username groupname`|Remove user from **secondary group**|
|`sudo gpasswd -a username groupname`|Add user to group (alternative)|
|`sudo gpasswd -d username groupname`|Remove user from group (alternative)|
|`sudo usermod -aG groupname username`|Add user to group (standard, works everywhere)|

### 3. VIEW GROUP INFO (Debian/Ubuntu)

|Command|What It Does|
|---|---|
|`groups username`|Show all groups for a user|
|`id username`|Show UID, GID, and all groups|
|`getent group groupname`|Show group info (including members)|
|`getent group \| grep username`|Find which groups a user belongs to|
|`members groupname`|List all users in a group (if `members` installed)|
|`sudo cat /etc/group \| grep groupname`|Directly view group entry|

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

| Method              | Syntax                                                       | Example               |
| ------------------- | ------------------------------------------------------------ | --------------------- |
| **Symbolic**        | `chmod u+rwx,g+rx,o-rwx file` or `chmod u=rwx,g=r,o=rw file` | `chmod u+x script.sh` |
| **Numeric (Octal)** | `chmod 755 file`                                             | `chmod 644 file.txt`  |
