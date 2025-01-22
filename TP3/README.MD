# TP3 Sécu : Linux Hardening

**Dans ce TP, vous allez renforcer la sécurité d'un OS Linux.**

Le sujet du TP va être court car je ne vais pas réinventer la roue, et je vais vous renvoyer vers des ressources fiables.

## Sommaire

- [TP3 Sécu : Linux Hardening](#tp3-sécu--linux-hardening)
  - [Sommaire](#sommaire)
  - [0. Setup](#0-setup)
  - [1. Guides CIS](#1-guides-cis)
  - [2. Conf SSH](#2-conf-ssh)
  - [4. DoT](#4-dot)
  - [5. AIDE](#5-aide)

## 0. Setup

Vous utiliserez une VM Rocky Linux pour dérouler ce TP.

## 1. Guides CIS

CIS est une boîte qui notamment édite des guides de configuration

- assez réputés
- pour sécuriser les installations des OS courants
- notamment les OS Linux

🌞 **Suivre un guide CIS**
```bash
[root@localhost ~]# rpm -q  autofs
package autofs is not installed

[root@localhost ~]# rpm -q avahi
package avahi is not installed

[root@localhost ~]# rpm -q dhcp-server
package dhcp-server is not installed

[root@localhost ~]# rpm -q bind
package bind is not installed

[root@localhost ~]# rpm -q dnsmasq
package dnsmasq is not installed

[root@localhost ~]# rpm -q samba
package samba is not installed

[root@localhost ~]# rpm -q vsftpd
package vsftpd is not installed

[root@localhost ~]# rpm -q dovecot cyrus-imapd
package dovecot is not installed
package cyrus-imapd is not installed

[root@localhost ~]# rpm -q nfs-utils
package nfs-utils is not installed

[root@localhost ~]# rpm -q ypserv
package ypserv is not installed

[root@localhost ~]# rpm -q cups
package cups is not installed

[root@localhost ~]# rpm -q rpcbind
package rpcbind is not installed

[root@localhost ~]# rpm -q rsync-daemon
package rsync-daemon is not installed

[root@localhost ~]# rpm -q net-snmp
package net-snmp is not installed

[root@localhost ~]# rpm -q tftp-server
package tftp-server is not installed

[root@localhost ~]# rpm -q squid
package squid is not installed

[root@localhost ~]# rpm -q httpd nginx
package httpd is not installed
package nginx is not installed

[root@localhost ~]# rpm -q xinetd
package xinetd is not installed

[root@localhost ~]# rpm -q xorg-x11-server-common
package xorg-x11-server-common is not installed

[root@localhost ~]# bash script.sh 
script.sh: line 9: postconf: command not found

- Audit Result:
 ** PASS **

 - Port "25" is not listening on a non-loopback network interface
 - Port "465" is not listening on a non-loopback network interface
 - Port "587" is not listening on a non-loopback network interface

[root@localhost ~]# ss -plntu
Netid           State            Recv-Q           Send-Q                     Local Address:Port                       Peer Address:Port           Process                                     
udp             UNCONN           0                0                              127.0.0.1:323                             0.0.0.0:*               users:(("chronyd",pid=705,fd=5))           
udp             UNCONN           0                0                                  [::1]:323                                [::]:*               users:(("chronyd",pid=705,fd=6))           
tcp             LISTEN           0                128                              0.0.0.0:22                              0.0.0.0:*               users:(("sshd",pid=738,fd=3))              
tcp             LISTEN           0                128                                 [::]:22                                 [::]:*               users:(("sshd",pid=738,fd=4)) 

[root@localhost ~]# bash script.sh 

- IPv6 is enabled

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** PASS **

 - System has no wireless NICs installed


[root@localhost ~]# rpm -q bluez
package bluez is not installed

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** PASS **
 - kernel module: "dccp" doesn't exist in "/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/kernel/net"
 - kernel module: "dccp" doesn't exist in "/usr/lib/modules/5.14.0-427.40.1.el9_4.x86_64/kernel/net"


[root@localhost ~]# bash script.sh 


 -- INFO --
 - module: "tipc" exists in:
 - "/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/kernel/net"
 - "/usr/lib/modules/5.14.0-427.40.1.el9_4.x86_64/kernel/net"

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:
 - kernel module: "tipc" is loadable
 - kernel module: "tipc" is not deny listed
- Correctly set:
 - kernel module: "tipc" is not loaded
[root@localhost ~]# bash script.sh 
script.sh: line 30: /usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/kernel/net/tipc: Is a directory
script.sh: line 30: /usr/lib/modules/5.14.0-427.40.1.el9_4.x86_64/kernel/net/tipc: Is a directory


 -- INFO --
 - module: "tipc" exists in:
 - "/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/kernel/net"
 - "/usr/lib/modules/5.14.0-427.40.1.el9_4.x86_64/kernel/net"
 - setting kernel module: "tipc" to "/bin/false"
 - denylisting kernel module: "tipc"

 - remediation of kernel module: "tipc" complete

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** PASS **
 - kernel module: "rds" doesn't exist in "/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/kernel/net"
 - kernel module: "rds" doesn't exist in "/usr/lib/modules/5.14.0-427.40.1.el9_4.x86_64/kernel/net"

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** PASS **
 - kernel module: "sctp" doesn't exist in "/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/kernel/net"
 - kernel module: "sctp" doesn't exist in "/usr/lib/modules/5.14.0-427.40.1.el9_4.x86_64/kernel/net"

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.ip_forward" is not set in an included file
 ** Note: "net.ipv4.ip_forward" may be set in a file that's ignored by the load procedure **
 - "net.ipv6.conf.all.forwarding" is not set in an included file
 ** Note: "net.ipv6.conf.all.forwarding" may be set in a file that's ignored by the load procedure **


- Correctly set:

 - "net.ipv4.ip_forward" is correctly set to "0" in the running configuration
 - "net.ipv6.conf.all.forwarding" is correctly set to "0" in the running configuration

[root@localhost ~]# bash test.sh 
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.route.flush = 1
[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.conf.all.send_redirects" is not set in an included file
 ** Note: "net.ipv4.conf.all.send_redirects" may be set in a file that's ignored by the load procedure **

 - "net.ipv4.conf.default.send_redirects" is not set in an included file
 ** Note: "net.ipv4.conf.default.send_redirects" may be set in a file that's ignored by the load procedure **



- Correctly set:

 - "net.ipv4.conf.all.send_redirects" is correctly set to "0" in the running configuration
 - "net.ipv4.conf.default.send_redirects" is correctly set to "0" in the running configuration

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.icmp_ignore_bogus_error_responses" is not set in an included file
 ** Note: "net.ipv4.icmp_ignore_bogus_error_responses" may be set in a file that's ignored by the load procedure **



- Correctly set:

 - "net.ipv4.icmp_ignore_bogus_error_responses" is correctly set to "1" in the running configuration

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.icmp_echo_ignore_broadcasts" is not set in an included file
 ** Note: "net.ipv4.icmp_echo_ignore_broadcasts" may be set in a file that's ignored by the load procedure **



- Correctly set:

 - "net.ipv4.icmp_echo_ignore_broadcasts" is correctly set to "1" in the running configuration

[root@localhost ~]# bash test.sh 
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.route.flush = 1
[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.conf.all.accept_redirects" is incorrectly set to "1" in the running configuration and should have a value of: "0"
 - "net.ipv4.conf.all.accept_redirects" is not set in an included file
 ** Note: "net.ipv4.conf.all.accept_redirects" may be set in a file that's ignored by the load procedure **

 - "net.ipv4.conf.default.accept_redirects" is incorrectly set to "1" in the running configuration and should have a value of: "0"
 - "net.ipv4.conf.default.accept_redirects" is not set in an included file
 ** Note: "net.ipv4.conf.default.accept_redirects" may be set in a file that's ignored by the load procedure **

 - "net.ipv6.conf.all.accept_redirects" is not set in an included file
 ** Note: "net.ipv6.conf.all.accept_redirects" may be set in a file that's ignored by the load procedure **

 - "net.ipv6.conf.default.accept_redirects" is not set in an included file
 ** Note: "net.ipv6.conf.default.accept_redirects" may be set in a file that's ignored by the load procedure **



- Correctly set:

 - "net.ipv6.conf.all.accept_redirects" is correctly set to "0" in the running configuration
 - "net.ipv6.conf.default.accept_redirects" is correctly set to "0" in the running configuration

[root@localhost ~]# bash test.sh 
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.route.flush = 1
[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.conf.all.secure_redirects" is not set in an included file
 ** Note: "net.ipv4.conf.all.secure_redirects" may be set in a file that's ignored by the load procedure **

 - "net.ipv4.conf.default.secure_redirects" is not set in an included file
 ** Note: "net.ipv4.conf.default.secure_redirects" may be set in a file that's ignored by the load procedure **



- Correctly set:

 - "net.ipv4.conf.all.secure_redirects" is correctly set to "0" in the running configuration
 - "net.ipv4.conf.default.secure_redirects" is correctly set to "0" in the running configuration

root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.conf.all.rp_filter" is incorrectly set to "0" in the running configuration and should have a value of: "1"
 - "net.ipv4.conf.all.rp_filter" is not set in an included file
 ** Note: "net.ipv4.conf.all.rp_filter" may be set in a file that's ignored by the load procedure **



- Correctly set:

 - "net.ipv4.conf.default.rp_filter" is correctly set to "1" in the running configuration
 - "net.ipv4.conf.default.rp_filter" is correctly set to "1" in "/usr/lib/sysctl.d/50-redhat.conf"

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.conf.all.log_martians" is not set in an included file
 ** Note: "net.ipv4.conf.all.log_martians" may be set in a file that's ignored by load procedure **

 - "net.ipv4.conf.default.log_martians" is not set in an included file
 ** Note: "net.ipv4.conf.default.log_martians" may be set in a file that's ignored by load procedure **



- Correctly set:

 - "net.ipv4.conf.all.log_martians" is correctly set to "1" in the running configuration
 - "net.ipv4.conf.default.log_martians" is correctly set to "1" in the running configuration

[root@localhost ~]# bash script.sh 

- Audit Result:
 ** FAIL **
 - Reason(s) for audit failure:

 - "net.ipv4.tcp_syncookies" is not set in an included file
 ** Note: "net.ipv4.tcp_syncookies" May be set in a file that's ignored by load procedure **



- Correctly set:

 - "net.ipv4.tcp_syncookies" is correctly set to "1" in the running configuration


```

```bash
[tom@TP3 ~]$ bash script.sh 

- Audit Result:
 *** PASS ***
- * Correctly set * :

 - File: "/etc/ssh/sshd_config":
 - Correct: mode (0600), owner (root), and group owner (root) configured
```

```bash
[tom@TP3 ~]$ bash script.sh 

- Audit Result:
 ** PASS **
 - * Correctly configured * :
 - No openSSH private keys found
```

```bash
[tom@TP3 ~]$ bash script.sh 

- Audit Result:
 ** PASS **
 - * Correctly configured * :
 - File: "/etc/ssh/ssh_host_ed25519_key.pub"
 - Correct: mode: "0644", owner: "root", and group owner: "root" configured
 - File: "/etc/ssh/ssh_host_ecdsa_key.pub"
 - Correct: mode: "0644", owner: "root", and group owner: "root" configured
 - File: "/etc/ssh/ssh_host_rsa_key.pub"
 - Correct: mode: "0644", owner: "root", and group owner: "root" configured
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -Pi -- '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-
cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se|chacha20-poly1305@openssh\.com)\b'
grep: the -P option only supports a single pattern
```

```bash
[tom@TP3 ~]$ sudo !!
sudo sshd -T | grep -Pi -- 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-
sha1|diffie-hellman-group-exchange-sha1)\b'
grep: the -P option only supports a single pattern
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -Pi -- 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-
64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-
sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'
grep: the -P option only supports a single pattern
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -Pi -- '^\h*(allow|deny)(users|groups)\h+\H+'
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -Pi -- '^banner\h+\/\H+'
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -Pi -- '(clientaliveinterval|clientalivecountmax)'
clientaliveinterval 0
clientalivecountmax 3
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -i disableforwarding
disableforwarding no

Edit the /etc/ssh/sshd_config file to set the DisableForwarding parameter to yes
above any Include entry as follows:

DisableForwarding yes

[tom@TP3 ~]$ sudo sshd -T | grep -i disableforwarding
disableforwarding yes
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep gssapiauthentication
gssapiauthentication yes
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep hostbasedauthentication
hostbasedauthentication no
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep ignorerhosts
ignorerhosts yes
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep logingracetime
logingracetime 60
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep loglevel
loglevel INFO
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep maxauthtries
maxauthtries 4
```

```bash
[tom@TP3 ~]$ sudo sshd -T | awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] > 10 || a[2] > 30 || a[3] > 60) print $0}}'
maxstartups 10:30:100
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -i maxsessions
maxsessions 10
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep permitemptypasswords
permitemptypasswords no
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep permitrootlogin
permitrootlogin no
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep permituserenvironment
permituserenvironment no
```

```bash
[tom@TP3 ~]$ sudo sshd -T | grep -i usepam
usepam yes
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/passwd
Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: { %g/ %G)' /etc/passwd-
Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: { 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group
Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group-
Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow
Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow-
Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow
Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow-
Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shells
Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
```

```bash
[tom@TP3 ~]$ sudo [ -e "/etc/security/opasswd.old" ] && stat -Lc
```

```bash
[tom@TP3 ~]$ rpm -q libselinux
libselinux-3.6-1.el9.x86_64
```

```bash
[tom@TP3 ~]$ sudo grubby --info=ALL | grep -Po '(selinux|enforcing)=0\b'
```

```bash
[tom@TP3 ~]$ grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config
SELINUXTYPE=targeted
```

```bash
[tom@TP3 ~]$ getenforce
Permissive
```

```bash
[tom@TP3 ~]$ sudo !!
sudo bash script.sh 

- Audit Result:
 ** PASS **
 - All audit configuration files are mode: "640" or more restrictive
```

```bash
[tom@TP3 ~]$ sudo find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root
```

```bash
[tom@TP3 ~]$ sudo find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root
```

```bash
[tom@TP3 ~]$ bash script.sh 

- Audit Result:
 ** PASS **
 - * Correctly configured * :
 - Audit tool "/sbin/auditctl" is correctly configured to mode: "0755"
 - Audit tool "/sbin/aureport" is correctly configured to mode: "0755"
 - Audit tool "/sbin/ausearch" is correctly configured to mode: "0755"
 - Audit tool "/sbin/autrace" is correctly configured to mode: "0750"
 - Audit tool "/sbin/auditd" is correctly configured to mode: "0755"
 - Audit tool "/sbin/augenrules" is correctly configured to mode: "0755"
```

```bash
[tom@TP3 ~]$ stat -Lc "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk '$2 != "root" {print}'
```

```bash
[tom@TP3 ~]$ stat -Lc "%n %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules |
awk '$2 != "root" {print}'
```
## 2. Conf SSH

🌞 **Chiffrement fort côté serveur**


https://learn.microsoft.com/fr-fr/viva/glint/setup/sftp-ssh-key-gen#create-an-ssh-key-pair-on-macintosh-or-linux
https://www.openssh.com/manual.html
https://www.ssh.com/academy/ssh/command
```bash
tom@Debian:~$ ssh-keygen -t rsa -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/home/tom/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/tom/.ssh/id_rsa
Your public key has been saved in /home/tom/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:xIv7EWtYsDaUInF+A9xixaIJhZWIktS0OYECtV1TIkU tom@Debian
The key's randomart image is:
+---[RSA 4096]----+
|=OO=+*E..        |
|O..BO+o=         |
|o.oB+o* o        |
|  o..+ * .       |
|      = S        |
|     . = o       |
|      o +        |
|       o .       |
|        .        |
+----[SHA256]-----+
```
```bash
tom@Debian:~/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZX[..........]zH7cKx1pnTglIHFNNVqBsFtxhQ1jbSyG97Sne6
f0kHt0VfnLZpWXzgMCsxXHl4rUTHc0SlIAuO1OJjrtZfuNTZgjs2RWJqnpOFup6C5sj888
WN+0GlkXxpsAAAAKdG9tQERlYmlhbgE=
-----END OPENSSH PRIVATE KEY-----

```
```bash
tom@Debian:~/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC61oZc1SzI2EcGFo26CbIUOTNBVx5Tlp2kY0GPaxkxkM7r2U4NavsqBV54BnLhEgDNVu21mUqzFzKwkOVvhwLNEE4WPZ8FpUbb5Uh+wVGabg2OYD8BCqCQUCjLrwD0N/wxUu5j7xs5HpEVbYe4fHlbrQeP1F6PBswHK8jfNBwLOPt4gPxBnTzNz1STP3UDnF+6NCdKHwClxhxmX/YxaBYBLmoUidKKxzl3rCJBikj4IsQE+n60ossH1In0SWk+n6yaGbQp5mQW3dNVZDxJR22AJ/Yu5hMdpOboalSTi3RJUiYwbknV9nclImEgCy1HLPq5whceoIJIMOqNdkc6SdUdy4Fvc4Ob2D8pXyspx5180F5y6bwI6tiprt2+T1zoUI3c8AS5ZIUGGZ21O9b3NER0fmC6W0lw0Vn1PT9/SC9Bb1KtpacA9HDhl63okAFvpr55pRosEGaDBPgKErbL7oZ3/Y3zJ6cDMa8zyCoWDoqQx4dP0pn7Kq2UucVkZfNtse83vDTBSL/5yHDZGxZbwfgL6HhqQhOF3CozoXIoaUziFr7hKwDFTYKPNECOnCUhIHsaevntwdvc+u8i1ia7tptr+tGih5GAD3xBXttMR8eVcWVmJk/CVnUVG3j9MXIZBKz03+LtavHgcXaJcGdaouvstdDynleJxG9qtv4Ihf0aPQ== tom@Debian

```
```bash
tom@Debian:~/.ssh$ ssh-copy-id -i ~/.ssh/id_rsa.pub tom@10.3.1.10     
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/tom/.ssh/id_rsa.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
tom@10.3.1.10's password: 

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'tom@10.3.1.10'"
and check to make sure that only the key(s) you wanted were added.
```
```bash
[tom@TP3 ~]$ sudo cat  /etc/ssh/sshd_config
[.......]
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
```
```bash
[tom@TP3 ~]$ sudo systemctl restart sshd
```
```bash
tom@Debian:~$ ssh tom@10.3.1.10
Last login: Mon Jan 13 10:44:48 2025 from 10.3.1.1
[tom@TP3 ~]$ 

```
```bash
[tom@TP3 ~]$ sudo openssl dhparam -out /etc/ssh/dh_param.pem 4096
Generating DH parameters, 4096 bit long safe prime
......................................................................................................................................+...............................................................................+.............................................................................................................................................................................................................................................+................................................................................................................................................................................................................................................................................................................................................................................................................................+...............................................................................................................................+......+............................................................................................................................................................................................................................................................................................................................+..............................................................................................................................................................................+............................................................................+................................................................................................+.................+..............+..........................................................................................................................................................................+...............................................................................................................+.........................................................................................................................................................................+......+..............................+.....................................................................................................+......................................................................................................................................+.................................................................................+........................................................................................................................................+...........................................................................................................................................................................................................................................................................................................................+....................................................+.................................................................................................................................................................................................................................................................................................................................................................................+...........................................................................................................................+..............................................................................................................................................................................................................+...............................................................................................................................................................................................................................................................................................+.....................+...........................................................................................................................................................................................................................................................+.......................................................+...........................................................................................................................................................................................................................................................................................................................+.............+...........................................................................................................................................................+............................................................................................................................................................................................................................................................................................................................................................................................................+.............................................................................+.................................................................+...................................+.................................................................................................................................................................................................................................................................................................+..............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................+..................................................................................................................................+.......................................................................................+..........................................
................................................................................+......................................+..........................................................................................................................................................................................................................+................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................+...........................................................................................................................................................................................................................................................................................................................+.........................................+.............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................+......................................+................................................................................+....................................+.......................................................................................................................+.....+............................................................+........................................................................+.................................................................................................................................................................................................................................................................................................................................................................................................................................++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*

```
```bash
[tom@TP3 ~]$ sudo cat  /etc/ssh/sshd_config
[.......]
PasswordAuthentication no
PermitRootLogin no
PubkeyA
KexAlgorithms diffie-hellman-group-exchange-sha256

```
```bash
[tom@TP3 ~]$ sudo systemctl restart sshd
```


🌞 **Clés de chiffrement fortes pour le client**

```bash
tom@Debian:~/.ssh$ ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519 -C "Thaume-SSH-TP3"        
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/tom/.ssh/id_ed25519
Your public key has been saved in /home/tom/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:JPSyGQV/HfzG2WIy2FA473DDfZfqbGtaTge3T0eIqC0 Thaume-SSH-TP3
The key's randomart image is:
+--[ED25519 256]--+
|      o..  +o    |
|     . +  +...   |
|      + + .B.+ o.|
|       B .o.O.Oo+|
|      o S .+.Bo+o|
|         o  ..o..|
|        E . oo oo|
|         .  +=..o|
|           .+o. .|
+----[SHA256]-----+
```
```bash
tom@Debian:~/.ssh$ ls
id_ed25519  id_ed25519.pub  id_rsa  id_rsa.pub  known_hosts  known_hosts.old
tom@Debian:~/.ssh$ cat id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1[.....]ujs=
-----END OPENSSH PRIVATE KEY-----
tom@Debian:~/.ssh$ cat id_ed25519.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILGnqjEq483y7jgfIW6tCyuRXYM0XI5ogg4LhP/16AaJ Thaume-SSH-TP3
remote system.
```
```bash
tom@Debian:~/.ssh$ ssh-copy-id -i ~/.ssh/id_ed25519.pub tom@10.3.1.10
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/tom/.ssh/id_ed25519.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'tom@10.3.1.10'"
and check to make sure that only the key(s) you wanted were added.
```

🌞 **Connectez-vous en SSH à votre VM avec cette paire de clés**
```bash
tom@Debian:~$ ssh -i ~/.ssh/id_ed25519 -vvvv tom@10.3.1.10
OpenSSH_9.2p1 Debian-2+deb12u4, OpenSSL 3.0.15 3 Sep 2024
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug2: resolve_canonicalize: hostname 10.3.1.10 is address
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts' -> '/home/tom/.ssh/known_hosts'
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts2' -> '/home/tom/.ssh/known_hosts2'
debug3: ssh_connect_direct: entering
debug1: Connecting to 10.3.1.10 [10.3.1.10] port 22.
debug3: set_sock_tos: set socket 3 IP_TOS 0x10
debug1: Connection established.
debug1: identity file /home/tom/.ssh/id_ed25519 type 3
debug1: identity file /home/tom/.ssh/id_ed25519-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u4
debug1: Remote protocol version 2.0, remote software version OpenSSH_8.7
debug1: compat_banner: match: OpenSSH_8.7 pat OpenSSH* compat 0x04000000
debug2: fd 3 setting O_NONBLOCK
debug1: Authenticating to 10.3.1.10:22 as 'tom'
debug3: record_hostkey: found key type ED25519 in file /home/tom/.ssh/known_hosts:3
debug3: record_hostkey: found key type RSA in file /home/tom/.ssh/known_hosts:4
debug3: record_hostkey: found key type ECDSA in file /home/tom/.ssh/known_hosts:5
debug3: load_hostkeys_file: loaded 3 keys from 10.3.1.10
debug1: load_hostkeys: fopen /home/tom/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug3: order_hostkeyalgs: have matching best-preference key type ssh-ed25519-cert-v01@openssh.com, using HostkeyAlgorithms verbatim
debug3: send packet: type 20
debug1: SSH2_MSG_KEXINIT sent
debug3: receive packet: type 20
debug1: SSH2_MSG_KEXINIT received
debug2: local client KEXINIT proposal
debug2: KEX algorithms: sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com
debug2: host key algorithms: ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256
debug2: ciphers ctos: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
debug2: MACs ctos: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
debug2: MACs stoc: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
debug2: compression ctos: none,zlib@openssh.com,zlib
debug2: compression stoc: none,zlib@openssh.com,zlib
debug2: languages ctos: 
debug2: languages stoc: 
debug2: first_kex_follows 0 
debug2: reserved 0 
debug2: peer server KEXINIT proposal
debug2: KEX algorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,kex-strict-s-v00@openssh.com
debug2: host key algorithms: rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519
debug2: ciphers ctos: aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
debug2: ciphers stoc: aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
debug2: MACs ctos: hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512
debug2: MACs stoc: hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512
debug2: compression ctos: none,zlib@openssh.com
debug2: compression stoc: none,zlib@openssh.com
debug2: languages ctos: 
debug2: languages stoc: 
debug2: first_kex_follows 0 
debug2: reserved 0 
debug3: kex_choose_conf: will use strict KEX ordering
debug1: kex: algorithm: curve25519-sha256
debug1: kex: host key algorithm: ssh-ed25519
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug3: send packet: type 30
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug3: receive packet: type 31
debug1: SSH2_MSG_KEX_ECDH_REPLY received
debug1: Server host key: ssh-ed25519 SHA256:zJ30a8vkO/MYUd04H2XXXO8MhUcwE8uB05yTOAb9SCQ
debug3: record_hostkey: found key type ED25519 in file /home/tom/.ssh/known_hosts:3
debug3: record_hostkey: found key type RSA in file /home/tom/.ssh/known_hosts:4
debug3: record_hostkey: found key type ECDSA in file /home/tom/.ssh/known_hosts:5
debug3: load_hostkeys_file: loaded 3 keys from 10.3.1.10
debug1: load_hostkeys: fopen /home/tom/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug1: Host '10.3.1.10' is known and matches the ED25519 host key.
debug1: Found key in /home/tom/.ssh/known_hosts:3
debug3: send packet: type 21
debug1: ssh_packet_send2_wrapped: resetting send seqnr 3
debug2: ssh_set_newkeys: mode 1
debug1: rekey out after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug3: receive packet: type 21
debug1: ssh_packet_read_poll2: resetting read seqnr 3
debug1: SSH2_MSG_NEWKEYS received
debug2: ssh_set_newkeys: mode 0
debug1: rekey in after 134217728 blocks
debug3: ssh_get_authentication_socket_path: path '/run/user/1000/openssh_agent'
debug1: get_agent_identities: bound agent to hostkey
debug1: get_agent_identities: ssh_fetch_identitylist: agent contains no identities
debug1: Will attempt key: /home/tom/.ssh/id_ed25519 ED25519 SHA256:JPSyGQV/HfzG2WIy2FA473DDfZfqbGtaTge3T0eIqC0 explicit
debug2: pubkey_prepare: done
debug3: send packet: type 5
debug3: receive packet: type 7
debug1: SSH2_MSG_EXT_INFO received
debug1: kex_input_ext_info: server-sig-algs=<ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com>
debug3: receive packet: type 6
debug2: service_accept: ssh-userauth
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug3: send packet: type 50
debug3: receive packet: type 51
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic
debug3: start over, passed a different list publickey,gssapi-keyex,gssapi-with-mic
debug3: preferred gssapi-with-mic,publickey,keyboard-interactive,password
debug3: authmethod_lookup gssapi-with-mic
debug3: remaining preferred: publickey,keyboard-interactive,password
debug3: authmethod_is_enabled gssapi-with-mic
debug1: Next authentication method: gssapi-with-mic
debug1: No credentials were supplied, or the credentials were unavailable or inaccessible
No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)


debug1: No credentials were supplied, or the credentials were unavailable or inaccessible
No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)


debug2: we did not send a packet, disable method
debug3: authmethod_lookup publickey
debug3: remaining preferred: keyboard-interactive,password
debug3: authmethod_is_enabled publickey
debug1: Next authentication method: publickey
debug1: Offering public key: /home/tom/.ssh/id_ed25519 ED25519 SHA256:JPSyGQV/HfzG2WIy2FA473DDfZfqbGtaTge3T0eIqC0 explicit
debug3: send packet: type 50
debug2: we sent a publickey packet, wait for reply
debug3: receive packet: type 60
debug1: Server accepts key: /home/tom/.ssh/id_ed25519 ED25519 SHA256:JPSyGQV/HfzG2WIy2FA473DDfZfqbGtaTge3T0eIqC0 explicit
debug3: sign_and_send_pubkey: using publickey with ED25519 SHA256:JPSyGQV/HfzG2WIy2FA473DDfZfqbGtaTge3T0eIqC0
debug3: sign_and_send_pubkey: signing using ssh-ed25519 SHA256:JPSyGQV/HfzG2WIy2FA473DDfZfqbGtaTge3T0eIqC0
Enter passphrase for key '/home/tom/.ssh/id_ed25519': 
debug3: send packet: type 50
debug3: receive packet: type 52
Authenticated to 10.3.1.10 ([10.3.1.10]:22) using "publickey".
debug1: channel 0: new session [client-session] (inactive timeout: 0)
debug3: ssh_session2_open: channel_new: 0
debug2: channel 0: send open
debug3: send packet: type 90
debug1: Requesting no-more-sessions@openssh.com
debug3: send packet: type 80
debug1: Entering interactive session.
debug1: pledge: filesystem
debug3: client_repledge: enter
debug3: receive packet: type 80
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug3: client_input_hostkeys: received RSA key SHA256:J5gwwqQpDeWKVuBujQuZIxT4RBNCNYTQ9RF7EkZLrdI
debug3: client_input_hostkeys: received ECDSA key SHA256:S5vCh37pQUmtu8bunHxcK0ZqfEi0QsR5qrZAbOmB9U8
debug3: client_input_hostkeys: received ED25519 key SHA256:zJ30a8vkO/MYUd04H2XXXO8MhUcwE8uB05yTOAb9SCQ
debug1: client_input_hostkeys: searching /home/tom/.ssh/known_hosts for 10.3.1.10 / (none)
debug3: hostkeys_foreach: reading file "/home/tom/.ssh/known_hosts"
debug3: hostkeys_find: found ssh-ed25519 key at /home/tom/.ssh/known_hosts:3
debug3: hostkeys_find: found ssh-rsa key at /home/tom/.ssh/known_hosts:4
debug3: hostkeys_find: found ecdsa-sha2-nistp256 key at /home/tom/.ssh/known_hosts:5
debug1: client_input_hostkeys: searching /home/tom/.ssh/known_hosts2 for 10.3.1.10 / (none)
debug1: client_input_hostkeys: hostkeys file /home/tom/.ssh/known_hosts2 does not exist
debug3: client_input_hostkeys: 3 server keys: 0 new, 3 retained, 0 incomplete match. 0 to remove
debug1: client_input_hostkeys: no new or deprecated keys from server
debug3: client_repledge: enter
debug3: receive packet: type 4
debug1: Remote: /home/tom/.ssh/authorized_keys:2: key options: agent-forwarding port-forwarding pty user-rc x11-forwarding
debug3: receive packet: type 4
debug1: Remote: /home/tom/.ssh/authorized_keys:2: key options: agent-forwarding port-forwarding pty user-rc x11-forwarding
debug3: receive packet: type 91
debug2: channel_input_open_confirmation: channel 0: callback start
debug2: fd 3 setting TCP_NODELAY
debug3: set_sock_tos: set socket 3 IP_TOS 0x10
debug2: client_session2_setup: id 0
debug2: channel 0: request pty-req confirm 1
debug3: send packet: type 98
debug1: Sending environment.
debug3: Ignored env SHELL
debug3: Ignored env SESSION_MANAGER
debug3: Ignored env WINDOWID
debug3: Ignored env QT_ACCESSIBILITY
debug3: Ignored env COLORTERM
debug3: Ignored env XDG_CONFIG_DIRS
debug3: Ignored env SSH_AGENT_LAUNCHER
debug3: Ignored env XDG_SESSION_PATH
debug3: Ignored env LANGUAGE
debug3: Ignored env SSH_AUTH_SOCK
debug3: Ignored env SHELL_SESSION_ID
debug3: Ignored env DESKTOP_SESSION
debug3: Ignored env GTK_RC_FILES
debug3: Ignored env XCURSOR_SIZE
debug3: Ignored env GTK_MODULES
debug3: Ignored env XDG_SEAT
debug3: Ignored env PWD
debug3: Ignored env XDG_SESSION_DESKTOP
debug3: Ignored env LOGNAME
debug3: Ignored env XDG_SESSION_TYPE
debug3: Ignored env SYSTEMD_EXEC_PID
debug3: Ignored env XAUTHORITY
debug3: Ignored env XKB_DEFAULT_MODEL
debug3: Ignored env GTK2_RC_FILES
debug3: Ignored env HOME
debug1: channel 0: setting env LANG = "en_US.UTF-8"
debug2: channel 0: request env confirm 0
debug3: send packet: type 98
debug3: Ignored env LS_COLORS
debug3: Ignored env XDG_CURRENT_DESKTOP
debug3: Ignored env KONSOLE_DBUS_SERVICE
debug3: Ignored env WAYLAND_DISPLAY
debug3: Ignored env KONSOLE_DBUS_SESSION
debug3: Ignored env PROFILEHOME
debug3: Ignored env XDG_SEAT_PATH
debug3: Ignored env QTWEBENGINE_DICTIONARIES_PATH
debug3: Ignored env INVOCATION_ID
debug3: Ignored env KONSOLE_VERSION
debug3: Ignored env MANAGERPID
debug3: Ignored env KDE_SESSION_UID
debug3: Ignored env XKB_DEFAULT_LAYOUT
debug3: Ignored env XDG_ACTIVATION_TOKEN
debug3: Ignored env XDG_SESSION_CLASS
debug3: Ignored env TERM
debug3: Ignored env USER
debug3: Ignored env COLORFGBG
debug3: Ignored env PLASMA_USE_QT_SCALING
debug3: Ignored env KDE_SESSION_VERSION
debug3: Ignored env PAM_KWALLET5_LOGIN
debug3: Ignored env QT_WAYLAND_FORCE_DPI
debug3: Ignored env DISPLAY
debug3: Ignored env SHLVL
debug3: Ignored env XDG_VTNR
debug3: Ignored env XDG_SESSION_ID
debug3: Ignored env XDG_RUNTIME_DIR
debug3: Ignored env XKB_DEFAULT_VARIANT
debug3: Ignored env QT_AUTO_SCREEN_SCALE_FACTOR
debug3: Ignored env JOURNAL_STREAM
debug3: Ignored env XCURSOR_THEME
debug3: Ignored env KDE_FULL_SESSION
debug3: Ignored env PATH
debug3: Ignored env DBUS_SESSION_BUS_ADDRESS
debug3: Ignored env KDE_APPLICATIONS_AS_SCOPE
debug3: Ignored env KONSOLE_DBUS_WINDOW
debug3: Ignored env _
debug2: channel 0: request shell confirm 1
debug3: send packet: type 98
debug3: client_repledge: enter
debug1: pledge: fork
debug2: channel_input_open_confirmation: channel 0: callback done
debug2: channel 0: open confirm rwindow 0 rmax 32768
debug3: receive packet: type 99
debug2: channel_input_status_confirm: type 99 id 0
debug2: PTY allocation request accepted on channel 0
debug2: channel 0: rcvd adjust 2097152
debug3: receive packet: type 99
debug2: channel_input_status_confirm: type 99 id 0
debug2: shell request accepted on channel 0
Last login: Mon Jan 13 12:15:48 2025 from 10.3.1.1
[tom@TP3 ~]$ 

```

## 4. DoT

Ca commence à faire quelques années maintenant que plusieurs acteurs poussent pour qu'on fasse du DNS chiffré, et qu'on arrête d'envoyer des requêtes DNS en clair dans tous les sens.

Le Dot est une techno qui va dans ce sens : DoT pour DNS over TLS. On fait nos requêtes DNS dans des tunnels chiffrés avec le protocole TLS.

🌞 **Configurer la machine pour qu'elle fasse du DoT**

```bash
[tom@TP3 ~]$ sudo dnf install  systemd-resolved -y
Last metadata expiration check: 0:03:50 ago on Thu 16 Jan 2025 02:42:21 PM CET.
Package systemd-resolved-252-46.el9_5.2.0.1.x86_64 is already installed.
Dependencies resolved.
Nothing to do.
Complete!
```
```bash
[tom@TP3 ~]$ sudo cat /etc/systemd/resolved.conf 
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it under the
#  terms of the GNU Lesser General Public License as published by the Free
#  Software Foundation; either version 2.1 of the License, or (at your option)
#  any later version.
#
# Entries in this file show the compile time defaults. Local configuration
# should be created by either modifying this file, or by creating "drop-ins" in
# the resolved.conf.d/ subdirectory. The latter is generally recommended.
# Defaults can be restored by simply deleting this file and all drop-ins.
#
# Use 'systemd-analyze cat-config systemd/resolved.conf' to display the full config.
#
# See resolved.conf(5) for details.

[Resolve]
# Some examples of DNS servers which may be used for DNS= and FallbackDNS=:
 Cloudflare: 1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com 2606:4700:4700::1001#cloudflare-dns.com
# Google:     8.8.8.8#dns.google 8.8.4.4#dns.google 2001:4860:4860::8888#dns.google 2001:4860:4860::8844#dns.google
# Quad9:      9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net
DNS=1.1.1.1
FallbackDNS=8.8.8.8
#Domains=
DNSSEC=yes
DNSOverTLS=yes
#MulticastDNS=no
#LLMNR=resolve
#Cache=yes
#CacheFromLocalhost=no
#DNSStubListener=yes
#DNSStubListenerExtra=
#ReadEtcHosts=yes
#ResolveUnicastSingleLabel=no

```
```bash
[tom@TP3 ~]$ sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
[tom@TP3 ~]$ sudo mv /etc/resolv.conf /etc/resolv.conf.bak
[tom@TP3 ~]$ sudo ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
[tom@TP3 ~]$ sudo systemctl restart systemd-resolved
```

🌞 **Prouvez que les requêtes DNS effectuées par la machine...**
```bash
[tom@TP3 ~]$ dig ynov.com

; <<>> DiG 9.16.23-RH <<>> ynov.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18313
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;ynov.com.                      IN      A

;; ANSWER SECTION:
ynov.com.               300     IN      A       104.26.11.233
ynov.com.               300     IN      A       172.67.74.226
ynov.com.               300     IN      A       104.26.10.233

;; Query time: 246 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Thu Jan 16 14:50:48 CET 2025
;; MSG SIZE  rcvd: 85
```

[Clique ici pour la capture 🦈](./Capture%20Dot.pcapng)

## 5. AIDE

Un truc demandé au point 1.3.1 du guide CIS c'est d'installer AIDE.

AIDE est un IDS ou *Intrusion Detection System*. Les IDS c'est un type de programme dont les fonctions peuvent être multiples.

Dans notre cas, AIDE, il surveille que certains fichiers du disque n'ont pas été modifiés. Des fichiers comme `/etc/shadow` par exemple.

🌞 **Installer et configurer AIDE**
```bash
[tom@TP3 ~]$ sudo aide --init
Start timestamp: 2025-01-22 19:13:08 +0100 (AIDE 0.16)
AIDE initialized database at /var/lib/aide/aide.db.new.gz

Number of entries:      40840

---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.new.gz
  MD5      : qNtoADVFBTxiUDA7CbqL5w==
  SHA1     : nyJWN10o2ssuem97ZMUpeM8T0fg=
  RMD160   : ugZf6wFlyuMRqS77vNrFwRwBWJQ=
  TIGER    : kgpHXxpBu7UWZdxMhg47D8K24e2m+UGV
  SHA256   : jWdKkQqJ4F8/fSVCvFaWlUzLIM7gOsss
             pnQHKqs7zpo=
  SHA512   : Sv+mc0E5Rj6cElmUgzsWeHt5zd95WxmS
             EN1C1+TxbjUr/SqlKN1Kk4E/Vj9ggIZ9
             h9895pcxRPV3bCq+2Z8aZg==


End timestamp: 2025-01-22 19:13:13 +0100 (run time: 0m 5s)

[tom@TP3 ~]$ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz


```


🌞 **Scénario de modification**
```bash
[tom@TP3 ~]$ sudo nano /etc/ssh/sshd_config
[tom@TP3 ~]$ sudo aide --check
Start timestamp: 2025-01-22 19:17:16 +0100 (AIDE 0.16)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      40840
  Added entries:                0
  Removed entries:              0
  Changed entries:              1

---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /etc/ssh/sshd_config

---------------------------------------------------
Detailed information about changes:
---------------------------------------------------

File: /etc/ssh/sshd_config
  SHA512   : eP83vneHRw8+Z3obZ/gLbGCKZVLz/JPR | NcRK+jCtGMxnJtr0VIfE7lORxiw11Rbx
             mCSVZ5e4YyVhED9xBSNMm6CHu/LY7tjq | uY/Zg+BpH6HG/KnSzKGysVMHQkp4k7eY
             Z011aHRt7C6NvbcFMfPv9g==         | By3YDo+d9QDdN3nIGXNREA==


---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.gz
  MD5      : qNtoADVFBTxiUDA7CbqL5w==
  SHA1     : nyJWN10o2ssuem97ZMUpeM8T0fg=
  RMD160   : ugZf6wFlyuMRqS77vNrFwRwBWJQ=
  TIGER    : kgpHXxpBu7UWZdxMhg47D8K24e2m+UGV
  SHA256   : jWdKkQqJ4F8/fSVCvFaWlUzLIM7gOsss
             pnQHKqs7zpo=
  SHA512   : Sv+mc0E5Rj6cElmUgzsWeHt5zd95WxmS
             EN1C1+TxbjUr/SqlKN1Kk4E/Vj9ggIZ9
             h9895pcxRPV3bCq+2Z8aZg==


End timestamp: 2025-01-22 19:17:23 +0100 (run time: 0m 7s)

```

🌞 **Timer et service systemd**
```bash
[tom@TP3 ~]$ sudo cat /etc/systemd/system/aide-check.timer
[Unit]
Description=Run AIDE Check every 10 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
Unit=aide-check.service

[Install]
WantedBy=timers.target
[tom@TP3 ~]$ 

[tom@TP3 ~]$ sudo systemctl enable aide-check.timer
Created symlink /etc/systemd/system/timers.target.wants/aide-check.timer → /etc/systemd/system/aide-check.timer.

[tom@TP3 ~]$ sudo systemctl start aide-check.timer
[tom@TP3 ~]$ sudo systemctl status aide-check.timer
● aide-check.timer - Run AIDE Check every 10 minutes
     Loaded: loaded (/etc/systemd/system/aide-check.timer; enabled; preset: disabled)
     Active: active (waiting) since Wed 2025-01-22 19:21:07 CET; 16s ago
      Until: Wed 2025-01-22 19:21:07 CET; 16s ago
 

Jan 22 19:21:07 TP3 systemd[1]: Started Run AIDE Check every 10 minutes.
[tom@TP3 ~]$ 



```
