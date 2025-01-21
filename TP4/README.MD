# 0. Setup

➜ **Machines Rocky Linux**

- on aura un serveur web et un reverse proxy (deux machines donc)

# I. Setup initial

| Machine      | IP          | Rôle                       |
| ------------ | ----------- | -------------------------- |
| `rp.tp5.b2`  | `10.5.1.11` | reverse proxy (NGINX)      |
| `web.tp5.b2` | `10.5.1.12` | serveur Web (NGINX oci) |

🌞 **Setup `web.tp5.b2`**

```
[tom@web ~]$ sudo mkdir -p  /var/www/app_nulle
[tom@web ~]$ cd /var/www/app_nulle/
[tom@web app_nulle]$ sudo nano idex.html
[tom@web app_nulle]$ sudo chown -R nginx:nginx /var/www/app_nulle
[tom@web app_nulle]$ sudo chmod -R 755 /var/www/app_nulle

```
```
[tom@web ~]$ sudo cat /etc/nginx/conf.d/app_nulle.conf
server {
    listen 80;

    root /var/www/app_nulle;
    index index.html;   
}
[tom@web ~]$ 
```
```
[tom@web ~]$ sudo systemctl start nginx
[tom@web ~]$ sudo systemctl status nginx
● nginx.service - The nginx HTTP and reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; disabled; preset: disabled)
     Active: active (running) since Fri 2025-01-17 10:48:02 CET; 5s ago
    Process: 49278 ExecStartPre=/usr/bin/rm -f /run/nginx.pid (code=exited, status=0/SUCCESS)
    Process: 49279 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
    Process: 49280 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
   Main PID: 49281 (nginx)
      Tasks: 2 (limit: 11115)
     Memory: 2.0M
        CPU: 15ms
     CGroup: /system.slice/nginx.service
             ├─49281 "nginx: master process /usr/sbin/nginx"
             └─49282 "nginx: worker process"

Jan 17 10:48:02 web.tp5.b2 systemd[1]: Starting The nginx HTTP and reverse proxy server...
Jan 17 10:48:02 web.tp5.b2 nginx[49279]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Jan 17 10:48:02 web.tp5.b2 nginx[49279]: nginx: configuration file /etc/nginx/nginx.conf test is successful
Jan 17 10:48:02 web.tp5.b2 systemd[1]: Started The nginx HTTP and reverse proxy server.
```
```
[tom@web var]$ sudo firewall-cmd --add-port=80/tcp --permanent
success
[tom@web var]$ sudo firewall-cmd --reload
success
      
[tom@web ~]$ 
```
```
[tom@web ~]$ sudo systemctl restart nginx
```
```

[tom@web app_nulle]$ curl 10.5.1.12
<!DOCTYPE html>
<html>
<head>
    <title>App Nulle</title>
</head>
<body>
    <h1>Bienvenue sur App Nulle!</h1>
</body>
</html>
```


🌞 **Setup `rp.tp5.b2`**
```
[tom@rp ~]$ sudo cat /etc/nginx/conf.d/nginx.conf 
server {
    listen 80;
    server_name app.tp5.b2;

    location / {
        proxy_pass http://10.5.1.12;
    }
}

```
```
[tom@rp ~]$ sudo systemctl status nginx
● nginx.service - The nginx HTTP and reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; disabled; preset: disabled)
     Active: active (running) since Fri 2025-01-17 11:06:13 CET; 10s ago
    Process: 49136 ExecStartPre=/usr/bin/rm -f /run/nginx.pid (code=exited, status=0/SUCCESS)
    Process: 49137 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
    Process: 49138 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
   Main PID: 49139 (nginx)
      Tasks: 2 (limit: 11115)
     Memory: 2.0M
        CPU: 16ms
     CGroup: /system.slice/nginx.service
             ├─49139 "nginx: master process /usr/sbin/nginx"
             └─49140 "nginx: worker process"

Jan 17 11:06:13 rp.tp5.b2 systemd[1]: Starting The nginx HTTP and reverse proxy server...
Jan 17 11:06:13 rp.tp5.b2 nginx[49137]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Jan 17 11:06:13 rp.tp5.b2 nginx[49137]: nginx: configuration file /etc/nginx/nginx.conf test is successful
Jan 17 11:06:13 rp.tp5.b2 systemd[1]: Started The nginx HTTP and reverse proxy server.

```
```
[tom@rp ~]$ sudo firewall-cmd --add-port=80/tcp --permanent
success
[tom@rp ~]$ sudo firewall-cmd --reload
success

```
```
[tom@rp ~]$ curl 10.5.1.12
<!DOCTYPE html>
<html>
<head>
    <title>App Nulle</title>
</head>
<body>
    <h1>Bienvenue sur App Nulle!</h1>
</body>
</html>
```
```
tom@Debian:~$ curl 10.5.1.12
<!DOCTYPE html>
<html>
<head>
    <title>App Nulle</title>
</head>
<body>
    <h1>Bienvenue sur App Nulle!</h1>
</body>
</html>
tom@Debian:~$ 

```

🌞 **HTTPS `rp.tp5.b2`**
```
[tom@rp ~]$ sudo firewall-cmd --add-port=443/tcp --permanent
[sudo] password for tom: 
success
[tom@rp ~]$ sudo firewall-cmd --reload
success
[tom@rp ~]$ 

```
```
[tom@rp ~]$ sudo openssl req -new -newkey rsa:4080 -days 365 -nodes -x509 -keyout /etc/pki/tls/private/server.key -out /etc/pki/tls/certs/server.crt
.+...+...+.......+...+..............+..................+....+........+...+...+..........+.....+.......+...+......++++++++++++++++++++++++++++++++++++++++++*..........+...............+..+...+..................+....+......+..+.........+.+...+............+..+.+..+.......+..++++++++++++++++++++++++++++++++++++++++++*.....+.............+...+...........+....+...............+..+...+....+..................+..+......+..........+............+..................+..+.......+..........................+.+......+..+.+......+...+..+.........+.+...............+......+.....+.......+....................................+....................+.+.....+.+..+.............+..+......+....+.....+..................+..........+..............+...+.+...............+..+.........+.+........+.......+............+.....................+..+.......+...+...+.........+..+...+.......+........+.+......+.....+...+.......+.....+......+............+......+.......+...+..+............+..........+.....+..........+...+..+...+.......+.....................+.........+...+........+......+.+...+..............+...+....+........+.+.....+....+.....+...+...+.+......+.................+......+.+......+.....+....+...+...+...+.................+....+...+..+...+.+.....+..........+.........+.....+.+.....+.......+..+..................+...+....+..+....+.........+.....+.+...........+...............................+..................+.........+..+...+............+....+.....+....+...+...+..+....+...............+...+.....+...+....+...+..+...............+.+.....+.........+......+....+...+.................+...+.......+...+..+.........+.+........+.+............+..+.+.....+.........+.+...........+.+.....+..........+.....+........................+..........+...+............+...+......+..............+.........................+..+.........+.......+..................+......+.........+......+.....+..................+......+.+...+...+.........+...+........+............+..........+..+....+.....+...............+....+.....+...............+.......+.....+.+.....+......................+...+...+..+............+.......+...+.....+...+...........................+...+....+......+.....+....+...+...........+......+.+..................+...............+...........+.+...+..............+......+......+......+.......+...........+......+...+................+............+..+...+....+...+..+....+......+......+.....+.......+...............+..+......+...+.......+..+..........+.....+.......+..............+.+......+..+......+.......+.........+...+...+..+.......+.....+....+.........+..+.+.....+.......+......+.........+...+.........+.....+..............................+.+........+.....................+....+.........+..+...+.......+....................+...+.+............+..............+.+........+.......+............+..+.+.........+.....+....+..+.......+...+...+..+...+....+.....+.+..............+.+.....+.......+...........................+..+.+...+.....................+.........+..........................+......+...+............+............................+.........+......+..+...+.........+...+...+.+........+......+.......+.....+..................+....+..................+.........+.........+.....................+..............+.+.....+...+.+......+..............+...........................+.............+.....+............+...+....+...........+..........+............+........+.+......+............+..+...+.+.........+......+............+........+.+.....+.+..+..............................+......+.+.....+......+......................+..+....+......+......+..............+....+..............+............+......+.............+.........+.....+...+...............+..........+...+......+...+..+.........+.........+.....................+.+...........+............+...............+...+.......+......+.....+....+..+....+...........+.+.....+....+...+.....+.............+...+..+...................+........+.............+..+.+.....+.+........+......................+....................+....+.........+......+..+.........+.........+....+...+........+.+...+...........................+....................+.+........+..........+..+............+.+..+....+...+...+.....+...+..........+...........+...+......+....+.....................+..+.........+...................+.....+.......+..+............+.........+..........+..............+.......+...+...+...+..+.........+......+.......+......+......+......+.................+.+.....+.......+..+.......+...+..+.............+.................+...+..........+.....+......+.+...........+.......+...+.........+.....+.........+............+.........+.+.....+............+.+......+...+..+.........+........................+.............+..............+.+..+...+....+.....+.+.................+.......+.........+++++
.+.........+........+.+.....+.+...+..++++++++++++++++++++++++++++++++++++++++++*.+......+...............+...++++++++++++++++++++++++++++++++++++++++++*.+.......+..+...+...+....+.....+............+.+...+......+......+.....+.......+..+.+...+..+...+............+.......+......+.....+...................+............+.....+.............+...+........+....+......+..............+.+......+.........+..+...+.........+...+....+.........+.....+.+........+.+......+.....+......+.........+.........+....+.....+..........+.....+.............+........+....+..+........................+....+..+...+................+..+...................+...........+..........+.....+.......+..+...+.......+.........+.....+.+........+...+......................+.................+.........................+......+...............+...+......+....................+.+...+.....+...........................+............+.......+.....+.+.......................+.......+........+.+.......................+.......+...+............+...........+...........................+......+.........+++++
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:
State or Province Name (full name) []:
Locality Name (eg, city) [Default City]:
Organization Name (eg, company) [Default Company Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:
Email Address []:
```
```
[tom@rp ~]$ sudo systemctl status nginx 
● nginx.service - The nginx HTTP and reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; disabled; preset: disabled)
     Active: active (running) since Fri 2025-01-17 12:17:15 CET; 1min 17s ago
    Process: 49849 ExecStartPre=/usr/bin/rm -f /run/nginx.pid (code=exited, status=0/SUCCESS)
    Process: 49850 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
    Process: 49851 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
   Main PID: 49852 (nginx)
      Tasks: 2 (limit: 11115)
     Memory: 2.6M
        CPU: 29ms
     CGroup: /system.slice/nginx.service
             ├─49852 "nginx: master process /usr/sbin/nginx"
             └─49853 "nginx: worker process"

Jan 17 12:17:15 rp.tp5.b2 systemd[1]: Starting The nginx HTTP and reverse proxy server...
Jan 17 12:17:15 rp.tp5.b2 nginx[49850]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Jan 17 12:17:15 rp.tp5.b2 nginx[49850]: nginx: configuration file /etc/nginx/nginx.conf test is successful
Jan 17 12:17:15 rp.tp5.b2 systemd[1]: Started The nginx HTTP and reverse proxy server.
```
```
[tom@rp ~]$ sudo cat /etc/nginx/conf.d/app.tp5.b2.conf 
server {
    listen 443 ssl;
    server_name app.tp5.b2;

    ssl_certificate     /etc/pki/tls/certs/server.crt;
    ssl_certificate_key /etc/pki/tls/private/server.key;

    location / {
        proxy_pass http://10.5.1.12;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name app.tp5.b2;

    return 301 https://$host$request_uri;
}
```


# II. Hardening script

Dans cette section, le coeur du sujet, vous allez développer un script `bash` qui permet de renforcer la sécurité de ces deux machines.

➜ **Votre script doit permettre de :**

- **configurer l'OS**
  - tout ce qui va être relatif au kernel
  - et tous les services basiques du système, comme la gestion de l'heure
  - éventuellement de la conf systemd, sudo, etc.
- **configurer l'accès à distance**
  - on pose une conf SSH robuste
- **gérer la conf NGINX**
  - votre script doit aussi proposer un fichier de conf NGINX maîtrisé et robuste
- **ajouter et configurer des services de sécurité**
  - on pense à fail2ban, AIDE, ou autres

> Réutilisez votre travail sur le sujet hardening du TP précédent évidemment. Réutilisez aussi ce que vous saviez déjà faire (bah si, non ?) comme fail2ban, ou l'application du principe du moindre privilège, la gestion de `sudo`. Enfin, soyez créatifs, c'est un exo libre.

➜ **N'hésitez pas à :**

- éclater le code dans plusieurs fichiers
- écrire des fonctions plutôt que tout à la suite

> Le but c'est de bosser sur le coeur du sujet : harden une machine Linux. En plus, être capable de l'automatiser comme ça on peut le lancer sur n'importe quelle nouvelle machine. Et aussi, vous faire prendre du skill sur `bash`.
