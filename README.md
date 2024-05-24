# Securing and Hardening a Linux System

![Screenshot 2023-10-06 200655](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/e25b7275-f2f1-465c-b9be-1d0e83f1060a)


## Introduction
In this project I demonstrate a number of different ways in which you can configure settings in Linux Ubuntu to enhance the security of the operating system. Although Linux is relatively secure and virus free out of the box, if you want enterprise level security for business purposes then you will need to configure it yourself. Here is a list of important steps you can take to secure your Linux system:
- Ensure Physical Security.
- Disable Booting from external media devices.
- Boot Loader Protection.
- Keep the OS Updated (only from trusted sources).
- Check the installed packages and remove unnecessary services.
- Check for Open Ports and stop the unnecessary ones.
- Enforce Password Policy
- Audit Passwords using John The Ripper.
- Eliminate unused and well-known accounts that are unnecessary.
- Give users limited administrative access.
- Do not use the root account on a regular basis and do not allow direct root login.
- Set limits using the ulimit command to avoid DoS attacks, such as launching a fork bomb.
- Implement File Monitoring (Host-based IDS - Tripwire).
- Scan for Rootkits, Viruses and Malware (Rootkit Hunter, chkrootkit, ClamAV).
- Use Disk Encryption to protect your data. Don’t forget to encrypt your backups as well.
- Secure every Network Service especially SSHd.
- Securing Your Linux System with a Firewall (Netfilter/Iptables).
- Monitor the firewall and its logs.
- Monitor your logs and search for suspicious activity (logwatch).
- Scan your servers using a VAS such as Nessus or OpenVAS.
- Make backups and test them.

## Securing the OpenSSH Server

- Configuring SSH settings by editing the sshd_config file located in /etc/ssh/ with the command `sudo nano /etc/ssh/sshd_config`.<br>

![Screenshot 2023-09-28 215038](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/7f02903a-a8e9-4bf0-82f3-2cfb3026d5c6)<br>

- Make sure to create a backup of the sshd file before you edit it.
- After editing the file you will have to restart the server so that the changes will come into effect.
- Change the default port of SSH from 22 to a random one of your own choosing will avoid you being seen by casual scans, but not targeted attacks: `Port 2278`.
- Due to most SSH attacks on the internet being automated, changing the default port is highly recommended.
- PermitRootLogin by default is set to prohibit-password but this still allows public key authentication and other such methods. It’s safer to disallow this one: `PermitRootLogin no`.
- Limit users SSH access by specifying the allowed users with: `AllowUsers user1 user2 user3`.
- Configure an idle timeout interval to automatically log out clients that have been inactive for a certain period of time: `ClientAliveInterval 300` and `ClientAliveCountMax 0`.
- Another good setting to configure is the `MaxAuthTries` and `MaxStartups`. <br>

![Screenshot 2023-09-28 220335](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/de7da639-1bcc-4ec3-92b4-7df6c562671d)<br>

- You can also restrict SSH access to only allow connections from certain IP addresses using `iptables` to specify the address: `iptables -A INPUT -p tcp --dport 2278 -s x.x.x.x -j ACCEPT` and drop all other incoming connections:`iptables -A INPUT -p tcp --dport 2278 -j DROP`.<br>

![Screenshot 2023-09-28 220156](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/bbb49f06-7f09-43a1-bb93-a11ec15c3560)

## Securing the Boot Loader

**Boot Sequence Order:**
1. BIOS executes MBR (Master Boot Record).
2. MBR executes GRUB2.
3. GRUB2 loads the kernel.
4. The kernel executes systemd which intialises the system.

**Physical Checklist:**
1. Physical Security (Kensington lock, etc).
2. Set up a BIOS password.
3. Configure the system to boot automatically from the Linux partition.
4. Set up a password for GRUB.

**Why is it important?**
- If a hacker has physical access to the computer they could alter grub and boot the system into a special mode of operation called single user mode where root is logged in automatically without a password.
- The attacker can also use the grub editor interface to change its configuration or gather information about the system.
- If its a dual boot system, the attacker can select at boot time another operating system which will ignore access controls and file permissions.

**How to Secure the Boot Loader**
- To address these issues, we will protect the grub bootloader with a password.
- Note that people with physical access to the files via other methods that grub cannot prevent, such as booting with a USB stick.
- You should setup a BIOS password as well and configure the system to boot automatically from the partition on which Linux is installed.
- We have to generate a hash password using a specific command: `grub-mkpasswd-pbkdf2` then enter your chosen password.<br>
  
![Screenshot 2023-09-28 220754](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/cd16b44d-1f67-4d8f-b03c-ec5bfec16c52)<br>

- It will generate a hashed form of the password.
- You then need to edit the grub main configuration file and add the hash of the password.
- That way your actual password is not visible in the grub scripts and a possible hacker cannot see it.
- You can view the main configuration file of GRUB2 using: `cat /boot/grub/grub.cfg`.
- It is not modified directly by the user, but by certain GRUB2 updates such as `update-grub2`.
- In fact, grub uses a series of scripts to  update this file.
- These are located in ls `/etc/grub.d`.
- Its best to change a custom file such as `40_custom` because it will not be overwritten even when the GRUB2 package is updated.
- Copy your hashed password, starting at the `grub.pbkdf2.sha512…`
- Open the custom file with: `sudo nano /etc/grub.d/40_custom`.<br>

![Screenshot 2023-09-28 221033](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/bed0be90-5f76-4fee-9832-c55f766b2b9b)<br>

  
- Add the line: `set superusers=”root”`.
- And on the next line: `passwd_pbkdf2 root HASHED PASSWORD`.<br>
  
![Screenshot 2023-09-28 222617](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/f5ba6858-55f1-4a1b-9ea3-265e42430bca)<br>

- Save the file and quit.
- Run the command to update the GRUB2 configuration file: `update-grub2`.<br>

![Screenshot 2023-09-28 223733](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/bc7be092-bef3-4c7a-8b05-25687416fdd9)<br>

- Now restart the system and you should be prompted for a password at boot.<br>

![Screenshot 2023-10-06 200002](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/ba222826-baa8-46b7-9a3f-3bbe2ad1cde9)

## Enforcing Password Policy
- Password policy is just as good as the strength of the users passwords.
- Password policies are a set of rules which must be satisfied. They usually include password age, length and complexity, number of login failures, and whether reusing old passwords is permitted.
- Password aging and length settings are defined in the following file: `sudo nano /etc/login.defs`.<br>

![Screenshot 2023-09-29 091249](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/081a9e6b-d789-4ae6-87d9-2002ab5a54a2)<br>

- Note that all the parameters in login.defs are only applicable to new accounts and not existing ones.
- You can configure the maximum number of days a password can be used, the minimum number of days allowed between password changes and the number of days warning given before the password expires.
- Another password settings that is not showed in the file but exists is PASS_MIN_LENGTH. You can add it to the file and set it to a length greater than 12, which is an acceptable length.
- You can use the command `man login.defs` to check any other parameters that you may want to add to your password policy.
- To change the password expiry policy for existing accounts use the `chage` command.
- For example, to change the number of days between password change, use the command `sudo chage -M 60 user`.
- You can check that the settings have worked using `sudo chage -l user`.<br>

![Screenshot 2023-09-29 092556](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/72d318e2-b049-4ea5-9831-1528414b8311)<br>

- To enforce password complexity on most Linux distributions we use PAM, which means pluggable authentication module.
- The configuration file for pam can be found in `/etc/pam.d/common-password` on Ubuntu based systems.
- To use PAM on Ubuntu based systems, make sure the following package is installed using: `sudo apt install libpam-pwquality`.
- Open the common password file in your favourite text editor: `sudo nano /etc/pam.d/common-password`.<br>

![Screenshot 2023-09-29 094607](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/4e908792-bae7-4777-b2a3-7c95b288b95e)<br>

- Find the line with pam_pwquality.so and add the following attributes: `retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1`.
- `retry=3` will prompt the user 3 times before exiting and returning an error.
- `minlen=12` specifies that the password can not be less than 12 characters.
- `difok=3` sets the minimum number of characters that must be different from the old password.
- `ucredit=-1` requires at least one uppercase character in the password.
- `lcredit=-1` requires at least one lowercase character in the password.
- `dcredit=-1` requires at least one numerical character in the password.
- `ocredit=-1` requires at least one special character in the password.<br>

![Screenshot 2023-09-29 094945](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/1c516974-3a3f-45e8-8fc5-7574409c197e)<br>

- Now that you have set these requirements, try to change your password to something that doesn’t meet the criteria and make sure that its all working!<br>

![Screenshot 2023-09-29 095338](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/14e495cc-8608-4412-ba45-271085d6c5f9)

## Locking or Disabling User Accounts
- There are several ways in which a user account can be locked or disabled.
- One way in which we can do this is to lock password authentication for the user. Note that this does not entirely lock the user out of the account - they will still be able to log in using SSH public key authentication if it’s set.
- Run the command: `sudo passwd -l user`.<br>

![Screenshot 2023-10-03 091451](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/52ba19aa-1624-40e6-9d93-28b53eddfa64)<br>

- To verify if the account is locked or disabled run the command: `sudo passwd --status user`. If you see a capital L it means its locked, NP means there is no password, and P means there is a valid password.
- You can also check the hash of the password using: `sudo cat /etc/shadow`. The password will have an ! at the front of it, which is not a valid file hash.<br>

![Screenshot 2023-10-03 091523](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/9894fc78-e458-4ca6-9e48-714c1b2a4ce2)<br>


- To unlock the user user account, use the command: `sudo passwd -u user`.<br>

![Screenshot 2023-10-03 091919](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/0eaad4c1-6cf0-497d-ae55-c52e7f3b20d6)<br>

- To completely disable an account, use the command: `sudo usermod --expiredate 1 user`. This sets the users account expiry date to 1 day after the Unix epoch, which is 00:00:00 UTC on 1 January 1 1970.
- To check the expiration date run: `sudo chage -l user` and you should see the expiration date as 02 January 1970.<br>

![Screenshot 2023-10-03 092218](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/d0566ddf-cbb3-4f8a-b81e-f5c1277c8725)<br>

- To reenable the account, you can use the command: `sudo usermod --expiredate "" user`.<br>

![Screenshot 2023-10-03 092329](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/4446984d-3349-4a8b-b677-9e6183b99c46)

## Giving Limited root Privileges
- In Linux, any administrative command that changes the system in any way should be run as root.
- The users that belong to the sudo group are allowed to run commands as root by using `sudo` before the command name.
- To see the users that belong to the sudo group run: `grep sudo /etc/group`.<br>

![Screenshot 2023-10-03 093050](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/9f180bba-b919-493a-8754-4b231fa3c729)<br>

- Initially, only the user that was created during system installation is allowed to run commands as sudo.
- The admin can add other users to the sudo group and they will be allowed to run commands as sudo aswell.
- The sudo command will request the password of the current user, not the root password.
- By running sudo su you can become root temporarily until you log out.
- One possible problem of this approach, is that such a user is allowed to run any commands as root. It’s not possible to restrict their access to some parts of the system or some commands.
- For example, if you want a user to be able to update a system without being able to change the configuration of the web server, the classical approach doesn’t allow that.
- We can give limited privilege access to users or groups and configure per command privilege access by editing the sudoers configuration file located at `/etc/sudoers`.
- Due to it being possible to break the system with improper syntax when editing this file, it is not recommended to edit the file directly with a normal text editor.
- Always use the visudo command instead, as it validates the syntax of the file before saving to ensure.
- By default, the command uses Vim as the text editor, but you can configure it using the command: `sudo update-alternatives --config editor`. I prefer to use nano.<br>

![Screenshot 2023-10-03 122115](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/1739844c-d5e4-4080-98ff-9fe3f9657d96)<br>

- For an example, I will make a new user called user1 and edit their privileges: `sudo useradd -d /home/user1 -m -s  /bin/bash user1`.
- For now, try running the command `sudo cat /etc/shadow` as user1.<br>

![Screenshot 2023-10-03 094628](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/0862f46c-7aa7-43cf-80bd-a00c11ef2049)<br>

- We get an error that user1 is not in the sudoers file and that the incident has been reported.
- Now, to edit the file run the command: `sudo visudo`. We are going to allow user1 to have root access to the commands `ls` and `cat`.
- In the # User privilege specification section, add the line: `user1 ALL=(root) /usr/bin/ls,/usr/bin/cat`.
- We need to provide the absolute file paths to the commands. These can be found using the command `which` for example `which cat`, `which ls` or `which apt`.

![Screenshot 2023-10-03 094907](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/b26131bc-9d0e-46c7-970b-3eb3e05197b6)<br>

- Try to run the command `sudo cat /etc/shadow` as user1. As you can see it works now.<br>

![Screenshot 2023-10-03 095013](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/3fcc07e4-e1e4-41b2-8f9d-d57c4c496b6b)<br>

- Try to also run the command `sudo apt update` as user1. You will find that you get an error.<br>

![Screenshot 2023-10-03 095048](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/90db6825-4da9-4dbd-8bc3-d29c992465bc)<br>

- You can also use `PASSWD:` and `NOPASSWD:` before the absolute paths to specify whether to prompt the user for a password when using these commands.
- You can also group users in the alias section of the configuration file to easily specify privileges for different departments in an organisation.
- For this we will need a second user account, so run the command: `sudo useradd -d /home/user2 -m -s  /bin/bash user2`.
- For example, in the #User alias specification section we will add the line: `User_Alias MYADMIN=user1,user2`.
- Then, in the #User privilege specification, add the line: `MYADMIN ALL=(root) /usr/bin/netstat,FILE`.<br>

![Screenshot 2023-10-03 122146](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/db4d5426-ab95-4a8c-93b3-4703ca319f6c)<br>

- Test out the commands on both accounts, it should be working.<br>

![Screenshot 2023-10-03 103520](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/e38a954b-8530-468a-a29d-31f62964f241)

- There, we have successfully set specific root privileges for different user accounts.

## Setting Users’ Limits (Running a DoS Attack Without root Access)
- There is an interesting denial of service attack called a ‘Fork Bomb’ or ‘Rabbit Virus’ which can be used to bring down an entire Linux system as an unprivileged user.
- Please don’t test this on a production system because it will make it unusable. If you want to test it out, run it on a VM.
- Create a bash script using the command:
`nano bomb`
- Inside the script, add the single line of code: `$0 && $0 &`.<br>

![Screenshot 2023-10-03 122523](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/b4e59ad2-7a66-43e8-9dd1-592dd4e996df)<br>

- Save the file, and edit the file permissions: `chmod +x bomb`.<br>

![Screenshot 2023-10-03 122804](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/27974140-8155-4a4d-b695-ee4a5169e792)<br>

- Now run the script, and the system will crash: `./bomb`.
- The only way to get out of this is to power cycle the machine.
- The script is very simple DoS attack which makes use of the fork system call to create an infinite number of processes.
- `$0` is a special variable which represents the script itself. So the script is running itself recursively two times and then is going in the background for another recursive call. `&` at the end puts the process in the background so new child processes cannot die and they start eating system resources.
- To protect the system from this sort of attack, we need to set a limit on the number of process a user can run.
- Using `ulimit -u` we can see the currently allowed number of processes allowed for the current user.<br>

![Screenshot 2023-10-03 125100](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/c45d97bf-4dc9-4dcb-ba74-f21d1b1ae810)<br>

- We can set the number of processes using the command: `sudo nano /etc/security/limits.conf`.
- At the end of the file, add the line: `user1 hard nproc 2000`.
- This will limit the user processes to 2000. Don’t make this too low otherwise the user will not be able to work properly on the system.
- You can also add a limit to a group by adding the line: `@group hard nproc 4000`<br>

![Screenshot 2023-10-03 131700](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/ebe3adb1-9701-467c-b522-bc3c4a1ab0e2)

- Now, log out and in again and try to run the ./bomb script again. As you can see, the system is still usable and did not crash.
- Use the `ulimit -u` command you can also double check to confirm that your changes in `/etc/security/limits.conf` have worked.<br>

![Screenshot 2023-10-03 131922](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/81242c69-03db-4b45-843c-684f8ca412df)<br>

- We have successfully mitigated the Fork Bomb attack on Linux and made the system more secure.

## Checking File Integrity with Tripwire
- One possible layer of security that may be applied to your Linux server is file integrity monitoring or file integrity verification.
- The purpose of monitoring and verifying the integrity of the important files including system binaries and configuration files is to make sure that the files have not been altered by unauthorised means.
- The unauthorised alteration of certain system files is one of the symptoms of an active attack or a compromised system.
- Once a hacker compromises a system they will start to modify configuration files, binaries and so on to consolidate their position and make it possible to return whenever they want.
- For example the `ls` and `ps` commands are often altered by rootkits so they don’t show files or processes belonging to the rootkit.
- There are a number of solutions used to monitor the integrity of critical system files, one of those being AIDE.
- Tripwire is a file integrity and monitoring or file integrity verification tool. It is a host-based IDS (HIDS).
- Tripwire works by taking a snapshot of the state of the system. Saving hashes, modification times, inode number, user group, file size and other data regarding the files defined by the administrator in the configuration files. This snapshot will be used to build a database.
- When you run an integrity test, Tripwire will compare the database against the real status of the system. If there are any chances between the existing snapshot and the test, Tripwire will detect it and report it to you.
- To install Tripwire, run the command: `sudo apt-get install tripwire`.<br>

![Screenshot 2023-10-11 083948](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/589c8856-8e31-4b47-989a-230276059060)<br>

- You will be prompted to create both a local keyfile and a site keyfile. Make sure you choose a passphrase of at least 12-14 characters with capitals, digits and special characters.
- First off, you can install the basic policy/configuration file by running the command: `twadmin -m P /etc/tripwire/twpol.txt`.<br>

![Screenshot 2023-10-11 115112](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/03dc20dc-75fb-4255-99ea-5e3521038a28)<br>

- Next, we will configure Tripwire. We will identify any unnecessary system files that should not be validated with the following steps. This process is done to eliminate any false alarms that result from unnecessary file entries that are included with the default policy file.
- First off, we will initialise the Tripwire database by running the command: `tripwire -m i`.<br>

![Screenshot 2023-10-11 140423](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/28ed596a-3bea-4d68-afc2-44db7de32a1e)<br>

- After initialising the database we will run a check scan, and pipe the sources of false alarms into a separate list to be removed from the original policy file: `tripwire -m c | grep Filename > deletefiles`.<br>

![Screenshot 2023-10-11 140837](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/ae9d9773-18f8-491b-81a4-a360e700b52b)<br>

- Open a new terminal window, and open the list of files you just created to be removed from the original policy file: `nano deletefiles`.<br>

![Screenshot 2023-10-11 093659](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/dc5a8371-839d-4544-82b2-8bc9aad125f0)

- To open and edit the policy file, run the command: `nano /etc/tripwire/twpol.txt`.<br>

![Screenshot 2023-10-11 093828](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/b1260273-d7aa-44f5-82ab-c4b31b90588b)
![Screenshot 2023-10-11 144314](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/7ddd1e2d-c67f-4c77-bf2a-09d4e8977f9d)<br>

- Files and directories can change in many ways. Some you may not consider important but others you’ll want to be reported.
- This policy file determines whether and how should report a file or directory as having changed and which attributes Tripwire should consider when scanning.
- By default, `tripwire -m i` checks a set of directories and files defined in `/etc/tripwire/twpol.txt` and creates the baseline database.
- Now, using the list in deletefiles, lets go through the policy file and comment out all the unnecessary system files by adding # at the start of the line.<br>

![Screenshot 2023-10-11 100204](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/1eb2e1d3-b424-410d-a909-ae1abc0e3a57)<br>

- The /proc file should be commented out because it gives a lot of error messages in the integrity scans for no reason at all. You should also add some specific /proc files that are important to be scanned for security reasons.
- You will also need to add the line /dev/pts as it is an important file system to scan and is not automatically included in the default policy file.

![Screenshot 2023-10-11 114724](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/b60cf0db-7def-40e5-8253-ded523f3c8c5)<br>

- And finally, we will comment out these /var directory files to avoid some common unnecessary error messages.<br>

![Screenshot 2023-10-11 114835](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/7fd8cf25-edf2-44da-a49f-232317b8359f)<br>

- Now that these changes have been made, we can run the `twadmin -m P /etc/tripwire/twpol.txt` command again to update the policy file.
  
![Screenshot 2023-10-11 115112](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/9652f737-8b5c-44cb-84cc-8af228369e4b)

- Now to test if Tripwire is working, we will need to initialise the database again. First, remove the initial database file you created using the command: `rm /var/lib/tripwire/HOSTNAME.twd`.<br>

![Screenshot 2023-10-11 151739](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/ff9db987-463d-491d-97c1-811f2332698f)<br>

- Next, run the the command to initialise the database again: `tripwire -m i`.

![Screenshot 2023-10-11 115526](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/ca9f2e8d-61d8-43c9-a8b1-63a79410cb00)<br>

- To emulate a file that a hacker would change, lets run the command: `echo "badguy:x:0:0:Bad Guy:/bin/bash" >> /etc/passwd`.<br>

![Screenshot 2023-10-11 121315](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/bceb6195-a1b7-457e-9116-9e87b4ba3c62)<br>

- Now we will run a system integrity check again, with the command: `tripwire -m c`.<br>

![Screenshot 2023-10-11 130249](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/384006d2-57d3-4027-90a1-fc32c19c75dc)

- As you can see, Tripwire was able to identify that files in the /etc directory have been edited.
- If after reviewing the changes and determining they are ok, it is recommended to update the Tripwire database with the new changes so they are not reported again on the next integrity check.
- You can update the database with the following command: `tripwire --update --twrfile /var/lib/tripwire/report/<name>.twr`.<br>

![Screenshot 2023-10-11 154625](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/3d483fca-7648-4069-a2f5-006df0dc647c)<br>

- Tripwire will show you the particular report using the default text editor. This is your chance to deselect files that you do not wish to be updated in the Tripwire database. It is important that you only allow authorised integrity violations to be changed in the database.
- All proposed updates to the Tripwire database start with a [x] before the file name. If you want to specifically exclude a valid violation from being added to the Tripwire database, remove the x from the box. To accept any files with an x beside them as changes, write the file in the editor and quit the text editor. This signals to Tripwire to alter its database and not report these files as violations.<br>

![Screenshot 2023-10-11 154548](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/2206ba6e-8cd9-4b10-bf4f-510848085ca9)

- Now run your integrity scan again: `tripwire -m c`.
- This time, Tripwire should not report the changes you made earlier since the database files have been updated.<br>

![Screenshot 2023-10-11 154748](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/0dd89bd1-8b9d-48cd-9dd2-5d95ed7b5269)

- You can also automate Tripwire using a cronjob and configure it to send you email reports with the changes every day.

## Scanning for Rootkits (rkhunter and chkrootkit)
- A rootkit is a collection of malicious computer software designed to enable access to a
computer that is not otherwise allowed.
- A rootkit contains malware that can steal data and take over a system for malicious purposes, all while remaining undetected.
- Typically, a hacker installs the rootkit after having obtained privileged access to the system.
- Obtaining this access is a result of a direct attack on the system, such as exploiting a known vulnerability or getting a valid password obtained by cracking or social engineering tactics such as phishing.
- After a successful intrusion into a system, usually the intruder will install a so-called
"rootkit" to secure further access.
- Once a rootkit is installed, it becomes possible to hide the intrusion as well as to maintain privileged access.
- A rootkit can hide a keylogger capturing your keystrokes and sending your confidential information to the hacker who controls it.
- It can also allow hackers to use your computer for illicit activities such as launching DoS attacks against other computers or sending out spam.
- Rootkit detection is difficult because a rootkit may be able to subvert the software that
is intended to find it, such as rootkit scanners and antivirus.
- Rootkits could remain in place for a very long time because their role is to hide any trail of their existence.
- Due to this, finding rootkits is a challenge especially if it loads kernel modules and compromises the kernel.
- By modifying kernel system calls, kernel rootkits can hide files, directories, processes or network connections without modifying any system binaries.
- If you discover that a system was compromised by a rootkit through any means, you MUST reinstall the entire system.
- NEVER TRUST A COMPROMISED MACHINE. EVER.
- To find rootkits on a Linux system we will use two tools: rkhunter and chkrootkit.
- It’s recommended to run these tools from a rescue disk, typically a live one. Or optionally, you can use an alternate directory from which to run all of the commands. This allows the rootkit scanner to use commands which have not been potentially compromised.

**Rkhunter**
- Rootkit Hunter is a security monitoring tool for Linux which scans for rootkits and other possible vulnerabilities.
- It does so by searching for the default directories of rootkits, misconfigured permissions. hidden files, kernel modules containing suspicious strings, and comparing hashes of important files with known good ones.
- It is written in Bash so it’s portable and can be run on any Linux based systems.
- To install rkhunter from the official Ubuntu repository, run: `sudo apt update && apt install rkhunter`.<br>

![Screenshot 2023-10-03 154700](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/9535a4b6-6cc4-44ae-90a6-1be478a15ce3)<br>

- After installing rkhunter and prior to running it, you’ll need to update the file properties database: `sudo rkhunter --propupd`.<br>

![Screenshot 2023-10-03 154756](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/f23464b0-c364-46be-81c6-a695a603147b)<br>

- To run a system check, use the command: `sudo rkhunter --check`.<br>

![Screenshot 2023-10-03 154932](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/2f336ada-5a68-4679-a1f8-95fe5ac29a0c)

- The results of the scan will be displayed in the terminal, and if anything suspicious is found, then a warning will be displayed.
- A log file of the test while be automatically created in `/var/log/`.
- You can also run a check which only displays the warnings with the command: `sudo rkhunter --check --report-warnings-only`.<br>

![Screenshot 2023-10-03 155125](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/8782404e-2a3d-4d80-9bad-2960cbf1c116)

- Out of the box, rkhunter will throw up some false warnings during the file property checks. This is because a few of the core utilities have been replaced by different scripts.
- For example, on this Ubuntu VM, rkhunter reports a warning for `usr/bin/lwp-request`. I know this is a false positive because I have just installed the system from a trustworthy source.<br>

![Screenshot 2023-10-03 154946](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/c8880951-542d-4d08-9918-b50ddc6d8142)

- These false positives can be ignored by whitelisting them in the rkthunter config file: `nano /etc/rkhunter.conf`.
- Add the line: `SCRIPTWHITELIST=/usr/bin/lwp-request`<br>
  
![Screenshot 2023-10-03 155447](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/0745d6b7-eb8d-4848-b700-336490d1427f)

**Chkrootkit**
- Check Rootkit is another tool which locally checks for rootkits.
- Install it by running: `sudo apt install chkrootkit`.<br>

![Screenshot 2023-10-03 155727](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/de52099c-0900-447c-b0c7-f5fd60eb10ed)<br>

- To start a scan, simply run as root: `sudo chkrootkit`.<br>

![Screenshot 2023-10-03 160058](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/38ae69e4-99e7-4090-953e-8997f9167ddb)<br>

- Note that a warning doesn’t necessarily mean that the system was compromised, it’s just a red flag that needs to be further investigated.
- The first thing you should do is search on google for chkrootkit and the warning it has displayed.
- We can also run it in quiet mode by running the `-q` option and it will print out only the warnings if there are any: `sudo chkrootkit -q`.
- It’s recommended to frequently run a cronjob that scans for rootkits.

# Scanning for Viruses with ClamAV
- If you run and use only Linux, an antivirus program is generally not necessary.
- Even though Linux is known as being mostly virus free, there are cases when installing an antivirus program and running scans is necessary.
- If you are running a Linux-based file server such as an FTP server or mail server, you’ll probably want to use an antivirus software.
- If you don’t, infected Windows computer may upload infected files to your Linux machine, allowing it to infect other Windows systems.
- The antivirus will actually scan for Windows malware and delete it. It isn’t protecting your Linux system, its protecting the Windows computers from themselves.
- ClamAV is the most popular open-source and free antivirus scanner available for Linux, Windows and Mac OS.
- ClamAV can quarantine or delete infected archived files, emails, websites and more.
- It has been around for a while and is most commonly used in an integrated fashion with mail servers for email scanning.
- To install, run the command: `sudo apt install && apt install clamav clamav-daemon`.<br>

![Screenshot 2023-10-03 162342](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/fc02cd6a-6061-4ebc-8f45-7e13c3dc247d)

- Lets take a look at the most important components of ClamAV, using: `man clamd`.
- The ClamAV daemon (clamd) loads the virus database definitions into memory and handles scanning of files when instructed to do so by clients such as `clamdscan`.
- The `clamdscan` utility allows you to scan the file system and asks `clamd` to scan a given set of files.
- There is also `clamscan`. The difference between `clamdscan` and `clamscam`, is that `clamscan` loads its own virus database and does the processing itself whereas `clamdscan` is a thin client for the clamd daemon which keeps its virus database in memory ready to use.
- In order to use `clamdscan`, you have to have `clamd` running.
- Using `clamdscan` is faster, but the memory consumption of `clamd` is quite high, around 1gb of RAM.
- The last component is the `freshclam` daemon. This is a tool that periodically checks for virus database definition updates, downloads and installs them, and notifies clamd to refresh its in memory virus database cache.
- After installing the ClamAV packages, we’ll have two services installed: clamav-freshclam and clamav-daemon.
- The status of the services can be checked by running: `sudo systemctl status clamav-freshclam` and `sudo systemctl status clamav-daemon`.<br>

![Screenshot 2023-10-03 162659](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/cdc69dcd-883d-4de5-841c-e7681149c88d)<br>

- By default clamav-freshclam will be running and clamav-daemon will be disabled.
- To start the ClamAV daemon, run the command: `sudo systemctl start clamav-daemon`.
- To enable the ClamAV to start at boot, run: `sudo systemctl enable clamav-daemon`.<br>

![Screenshot 2023-10-03 162732](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/78a0e523-3e8b-42fb-91fc-a73c1ba034f5)<br>

- Once the ClamAV daemon has finished starting up, we will run a test scan.
- First, lets download an EICAR test malware file by running: `wget www.eicar.org/download/eicar.com`.
- Now, run: `clamdscan --fdpass`.<br>

![Screenshot 2023-10-03 164046](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/f8343e67-417b-4b45-a68e-a82c7b7e3461)<br>

- If you want to quarantine infected files, pass the `--move` option, which moves the files to a specific directory.
- Create your quarantine directory by running: `mkdir /quarantine`.<br>

![Screenshot 2023-10-03 164139](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/71b9b186-0b3f-4edf-b18b-9c20124e85a7)<br>

- Now you can the the command: `clamdscan --move=/quarantine --fdpass /root`.<br>

![Screenshot 2023-10-03 164247](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/e0c9e2a7-c630-47e0-9782-78eb8307dd98)<br>
![Screenshot 2023-10-03 164312](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/96c75dad-7868-4caf-b24a-a74a6141be0f)<br>

- Now lets take a look at `clamscan`, which is a bit slower, but is more simple and uses less RAM as it does not require the ClamAV daemon.
- First, stop the ClamAV daemon by running: `systemctl stop clamav-daemon`.
- Then, for example, you can run a scan using: `clamscan --recursive /etc`.<br>

![Screenshot 2023-10-03 164440](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/5a5cc214-2e46-44fe-a977-eec41189e827)
![Screenshot 2023-10-03 164503](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/f8c3ac37-88db-4d17-af3f-45cba10d34c2)<br>

- If you want to only print out the infected files, you can include the `--infected` option.
- Also, if you want to automatically remove infected files, use the `--remove` option.

![Screenshot 2023-10-03 164701](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/90b22dca-797a-4c93-970e-13c6c71c8222)

- We have successfully scanned and removed viruses running on the system.

## Full Disk Encryption Using dm-crypt and LUKS
- In this section, I will demonstrate how to keep your data secure by encrypting disks and partitions in Linux.
- I’m going to encrypt an entire USB stick using dm-crypt and LUKS.
- You can follow the same steps if you want to encrypt a hard disk partition or an external USB hard drive.
- The following commands will destroy all data on the disk, so I encourage you to back up and migrate important files before continuing.
- Keep in mind this is a full disk encryption solution for Linux-based systems.
- If you want to access the encrypted disk on Windows or Mac, you must install another software.
- For example on Windows, you must install LibreCrypt to access the encrypted files.
- The first step is to install cryptsetup if it’s not already on your system: `sudo apt install cryptsetup`.<br>

![Screenshot 2023-10-10 102921](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/28f31803-89fc-40df-8f2f-d2856da38466)<br>

- The next step is optional but recommended and consists of filling the partition you want to encrypt with random data.
- This will ensure that the outside world will see this as random data and protect against disclosure of usage patterns.
- Insert the USB drive and check the drive name and details using: `fdisk -l`.<br>

![Screenshot 2023-10-03 172626](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/1fc756f4-b939-4128-b36d-84b4ffe9c41a)<br>

- If you want to encrypt only a partition and not the entire disk, use that partitions name.
- The following command will remove all data on the disk or partition you are encrypting: `dd if=/dev/urandom of=/dev/DRIVE status=progress`.<br>

![Screenshot 2023-10-03 173524](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/92eea9e6-bc5d-48bf-92ad-543dad60d746)<br>

- The next step will initialise the LUKS partition and set the initial passphrase.
- The command will fail if the partition is already mounted, so unmount it if that’s the case: `cryptsetup -y -v luksFormat /dev/DRIVE`.<br>

![Screenshot 2023-10-03 173706](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/aaecd841-a5e9-4543-aa3e-0fc149abfc97)<br>

- After verifying the passphrase it displays command successful.
- The next step is to open the encrypted device and setup a mapping name after successful verification of the supplied passphrase: `cryptsetup luksOpen /dev/DRIVE secretdata`.<br>

![Screenshot 2023-10-03 173819](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/a81de392-957b-4702-9525-5a9fdd1642de)<br>

- The command has created a mapping between the disk and the special device file called secretdata in `/dev/mapper`.
- To format the file system, run the command: `mkfs.ext4 /dev/mapper/secretdata`.
- EXT4 is the most commonly used file system for Linux.<br>

![Screenshot 2023-10-03 174130](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/a6cc1886-a647-40da-95ab-b7bde3eed376)<br>

- Finally, we mount the encrypted file system to the main file tree: `mount dev/mapper/secretdata /mnt`.<br>

![Screenshot 2023-10-10 103943](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/f9857177-6d23-4b29-abe7-8cd2593ec7a1)<br>

- At this point, you can use the mounted disk normally. You can copy move or erase files on the disk as per usual.
- The contents of the disk will be in `/mnt`.
- You can also create a new directory and mount the encrypted disk to that directory: run `mkdir /root/secretdata` and then `mount /dev/mapper/secretdata /root/secretdata`.<br>

![Screenshot 2023-10-10 103905](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/ce0512c9-49a3-4c57-bc20-b693eea00638)<br>

- I can now access the disk from both `/mnt` and `/root/secretdata`.<br>

![Screenshot 2023-10-03 174810](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/4da5e7e9-ac0a-4445-b973-f9df4c5a0c9c)<br>

- Data is protected at rest, and when the disk is not mounted. To unmount the disk, run: `umount /mnt` and `umount /root/secretdata`.<br>

![Screenshot 2023-10-03 175029](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/908d381c-5fa6-433e-8021-a90ba59eb3bb)<br>

- After unmounting the directory, we must also close the LUKS volume: `cryptsetup luksClose secretdata`.<br>

![Screenshot 2023-10-03 175126](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/9026f089-8f3d-4210-90a4-7b6859356020)<br>

- To make LUKS more secure, we can also a secret key authentication method for unlocking our encrypted drive.
- We are going to use the `dd` command and dev/urandom to generate a secret key: `dd if=/dev/urandom of=/root/keyfile bs=1024 count=4`.<br>

![Screenshot 2023-10-03 175247](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/95025d5d-1609-4c9e-bb2e-1d4d4f8754ac)

- To take a look at our random keyfile, run: `cat /root/keyfile`.<br>

![Screenshot 2023-10-03 175324](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/8a3c5a16-1810-464e-a886-4e8c8a7d50ff)<br>

- We will make the keyfile only readable by root. If a hacker managers to get root access then you have a bigger problem anyway: `chmod 400 /root/keyfile`.
- To confirm the permission run: `ls -l /root/keyfile`.<br>

![Screenshot 2023-10-03 175525](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/c3199104-4048-4eca-a5ed-8879fc5ce7c3)<br>

- We have a USB disk that is already set up, and we are going to add the keyfile as an additional authorisation method: `cryptsetup luksAddKey /dev/DRIVE /root/keyfile` .
- Now, to unlock your drive using the keyfile, run: `cryptsetup luksOpen /dev/DRIVE secretdata --key-file /root/keyfile`.<br>

![Screenshot 2023-10-03 175801](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/3f63b6ca-2d26-46cc-bedc-b52cfb6218af)<br>

# Symmetric Encryption Using GnuPG

- In this section we will encrypt a file using GPG.
- There are two types of encryption: symmetric (private key encryption) and asymmetric (public key encryption).
- The two most commonly used encryption methods are AES for symmetric encryption, and RSA or ECSDA for asymmetric encryption.
- Once a file is encrypted, it can be decrypted by anyone who has the password or passphrase.
- This can be useful for encrypting your own files locally or for encrypting a file before sending it to someone else.
- If you choose to send the encrypted file to someone else over an insecure channel like the internet, you’ll have to make sure you send the passphrase via a more secure method.
- There are two formats of output you can get, binary and text. The binary version will take up less space, but the text version is usually preferrable when you want to use it as text E.g. copy and pasting it into an email.
- For our example, lets first create a simple text file and write a secret message (”This is very secret information in a sensitive file”): `nano secret.txt`.<br>

![Screenshot 2023-10-04 155040](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/98f81a66-416c-49ca-946a-d9793ca2a09c)<br>

- To encrypt the file, run the command: `gpg -c secret.txt` .<br>
- It will prompt you for a passphrase, make sure you make this complex, at least 12-14 character with numbers and special characters included.

![Screenshot 2023-10-04 155135](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/ab002012-cd03-4d13-bcd5-8d6b1317a4de)<br>

- In the same directory, a new file will have appeared called `secret.txt.gpg`. This is the encrypted file in binary form. Check the contents using: `cat secret.txt.gpg`<br>

![Screenshot 2023-10-04 155215](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/042e8771-5280-4abf-9d46-93e481e43254)
![Screenshot 2023-10-04 155322](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/6e010fb6-7b93-4b7e-a667-3ae668bbd5e0)<br>

- By default, GPG uses AES-256 as the encryption algorithm. This is very secure, but if you want to change this for an reason you can use the `--cipher-algo` option. You can also specify the name of the output file with the `-o` option: `gpg -c --cipher-algo blowfish -o secret_blowfish.txt.gpg secret.txt`<br>

![Screenshot 2023-10-04 155643](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/77425ab4-4561-4902-b35d-a32487c92ccc)<br>

- Next, we should probably remove the clear text file, using the shred command which overwrites the file many times before deleting it. This makes it very difficult to recover the contents of the file: `shred -vu -n 100 secret.txt`.<br>

![Screenshot 2023-10-04 155806](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/af5d2786-2ee2-4ace-b7d5-6b42e125dd04)<br>

- When you want to decrypt your file, run: `gpg -o secret.txt -d secret.txt.gpg`.<br>

![Screenshot 2023-10-04 155927](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/53ed7b0b-5121-495d-b1a5-d689b4ba1ab7)

- The tool will automatically determine if it symmetrically or asymmetrically encrypted and the encryption algorithm.
- To produce an encrypted ASCII format for text based uses of the encrypted file, use the `-a` option: `gpg -ca secret.txt`.
- This will create a file called `secret.txt.asc`.<br>

![Screenshot 2023-10-04 160043](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/0b2e9472-9e32-4669-b6e9-025689042f02)

# Steganography

- Steganography is the art of hiding secret information in plain-text or in clear-sight.
- Steganographic tools can easily embed secret files into images, movies, audio files or other file formats.
- The word steganography comes from the Greek word “steganos” which means “hidden” and “graph” or “graphia” which means writing.The purpose of steganography is to hide even the mere existence of the message that is being sent.

**Use Cases**

- Sending encrypted messages without raising suspicion, such as in countries where free speech is suppressed.
- Digital watermark of the copyright holder.
- Hiding or transporting secret information (secret documents, Bitcoin private key etc).
- Transporting sensitive data from point A to point B such that the transfer of the data is unknown.

**Steps**

1. The secret file is encrypted.
2. The encrypted secret file is embedded into a cover file  according to a steganographic algorithm.  The cover file that contains the secret message or the embedded file is called stego file.
3. The stego file is sent normally (in clear-text or encrypted) to the destination or is made public to be easily reached.

**How to**

- First, we need to install the steganography tool, steghide: `sudo apt install steghide`.<br>

![Screenshot 2023-10-06 090115](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/7fb47af9-61a8-47b3-a6dc-fd626b61853e)<br>

- In this example, we will use an image as the cover file, and secretmessage.txt as the file to be embedded.
- Make sure you have both files in the same directory, where you will be executing steghide.
- First, make a copy of the image file: `cp img.jpg img_original.jpg`.<br>

![Screenshot 2023-10-06 090419](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/cf783b25-3e10-428d-8acc-0c42c13eb00f)<br>

- Let’s check the hashes of the images to confirm as a baseline that they are the same: `sha256sum img*`.<br>

![Screenshot 2023-10-06 090445](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/f5ce81b7-779e-4345-a1b6-faa3559f3ef6)<br>

- Let’s see what the capacity is of the carrier file: `steghide info img.jpg`.<br>

![Screenshot 2023-10-06 090525](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/a61f0e72-2f90-4500-b2e7-ef7e428f8fea)<br>

- Let's create an example secret message to be embedded into the the image.<br>

![Screenshot 2023-10-06 090759](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/a6dd3805-7337-42ae-8aa4-48256ccc00cb)<br>

- Now, to embed the text file into the image, run the command: `steghide embed -cf img.jpg -ef secretmessage.txt`.<br>

![Screenshot 2023-10-06 090856](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/1a662e5e-6d1c-4e01-b865-7adcfafc0dfe)

- Now, it will ask for a passphrase. Make sure you use a length of at least 12-14 characters and include numbers and special characters.
- Take a look at both images, as you can see they look identical to the naked eye.<br>

![Screenshot 2023-10-06 091326](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/8663dfa8-0faf-4fd5-8662-361a162b22bd)<br>

- The easiest way to determine if there is a secret message hidden inside the file, would be to compare the two files using a hash algorithm.
- Run the hash algorithm again: `sha256sum img*`. You will notice now that the hashes of the two files are different.<br>

![Screenshot 2023-10-06 091420](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/0ff46136-0a97-4e74-911a-c5c7a23281a2)<br>

- To extract the hidden embedded file, run the command: `steghide extract -sf img.jpg`.<br>

![Screenshot 2023-10-06 091523](https://github.com/Lachiecodes/Securing-and-Hardening-a-Linux-System/assets/138475757/e2bbf7bc-99a2-4857-912b-049ad9832e88)<br>

- In a real world steganography case, you should ALWAYS use unique images, as that way, there will be no way for the intercepted messages to be verified against the original unless someone has access to your files.
- There is one other way to determine that a file is using stenography, called steganalysis. The problem is generally handled with statistical analysis, similiar to cryptanalysis.
- In practice, however, it is extremely complicated to break steganography.

