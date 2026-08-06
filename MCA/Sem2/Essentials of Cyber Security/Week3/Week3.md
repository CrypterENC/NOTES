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
|                                         |                                                         |
### 2. PASSWORD MANAGEMENT
|Command|What It Does|
|---|---|
|`sudo passwd username`|Set or change user password|
|`sudo passwd -d username`|Delete password (user can login with **empty** password)|
|`sudo passwd -l username`|**Lock** the account (prefix `!` in `/etc/shadow`)|
|`sudo passwd -u username`|**Unlock** the account|
|`sudo passwd -e username`|Force password change on **next login**|
|`sudo passwd -S username`|Show password **status** (locked, last change, etc.)|
|`sudo passwd -n 7 username`|Minimum **7 days** before password can be changed|
|`sudo passwd -x 90 username`|Password **expires** after 90 days|
|`sudo passwd -w 7 username`|Warn user **7 days** before expiry|
|`sudo passwd -i 30 username`|Account **inactive** after 30 days of password expiry|
### 3. USER DELETION

|Command|What It Does|
|---|---|
|`sudo userdel username`|Deletes user account **but keeps** home directory|
|`sudo userdel -r username`|Deletes user **and** home directory + mail spool|
|`sudo userdel -f username`|Force delete (even if user is logged in)|




## Groups
## Managing Groups[^1]

[^1]: 
