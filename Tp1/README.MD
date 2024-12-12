# I. Init

- [I. Init](#i-init)
  - [1. Installation de Docker](#1-installation-de-docker)
  - [2. Vérifier que Docker est bien là](#2-vérifier-que-docker-est-bien-là)
  - [3. sudo c pa bo](#3-sudo-c-pa-bo)
  - [4. Un premier conteneur en vif](#4-un-premier-conteneur-en-vif)
  - [5. Un deuxième conteneur en vif](#5-un-deuxième-conteneur-en-vif)

## 2. Vérifier que Docker est bien là
```bash
# est-ce que le service Docker existe ?
systemctl status docker

# si oui, on le démarre alors
sudo systemctl start docker

# voyons si on peut taper une commande docker
sudo docker info
sudo docker ps
```

```
tom@Debian:~$ systemctl status docker
● docker.service - Docker Application Container Engine
     Loaded: loaded (/lib/systemd/system/docker.service; enabled; preset: enabled)
     Active: active (running) since Wed 2024-12-11 10:36:17 CET; 28min ago
TriggeredBy: ● docker.socket
       Docs: https://docs.docker.com
   Main PID: 5844 (dockerd)
      Tasks: 17
     Memory: 28.8M
        CPU: 427ms
     CGroup: /system.slice/docker.service
             └─5844 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock

```


## 3. sudo c pa bo
🌞 **Ajouter votre utilisateur au groupe `docker`**
```
tom@Debian:~$ sudo usermod -aG docker tom
tom@Debian:~$ newgrp docker
tom@Debian:~$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

```

tom@Debian:~$ alias dk='docker'
tom@Debian:~$ source ~/.bashrc
tom@Debian:~$ dk ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES


```

## 4. Un premier conteneur en vif



🌞 **Lancer un conteneur NGINX**
```
tom@Debian:~$ dk run -d -p 9999:80 nginx
9a13b95c572450745a165b21a50ecfdcba6bc44c30f871da1c1f4e65b2c70585
docker: Error response from daemon: driver failed programming external connectivity on endpoint stoic_newton (0b5beaacb205725230aa205032a1ed58340413344ca535505827cf2106b990cf): Bind for 0.0.0.0:9999 failed: port is already allocated.
```



🌞 **Visitons**

```
tom@Debian:~$ dk ps
CONTAINER ID   IMAGE     COMMAND                  CREATED              STATUS              PORTS                                     NAMES
2dc20e0fe7df   nginx     "/docker-entrypoint.…"   About a minute ago   Up About a minute   0.0.0.0:9999->80/tcp, [::]:9999->80/tcp   musing_hodgkin
```

```
tom@Debian:~$ dk logs 2d
/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
/docker-entrypoint.sh: Sourcing /docker-entrypoint.d/15-local-resolvers.envsh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
/docker-entrypoint.sh: Configuration complete; ready for start up
2024/12/11 10:12:58 [notice] 1#1: using the "epoll" event method
2024/12/11 10:12:58 [notice] 1#1: nginx/1.27.3
2024/12/11 10:12:58 [notice] 1#1: built by gcc 12.2.0 (Debian 12.2.0-14) 
2024/12/11 10:12:58 [notice] 1#1: OS: Linux 6.1.0-28-amd64
2024/12/11 10:12:58 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1048576:1048576
2024/12/11 10:12:58 [notice] 1#1: start worker processes
2024/12/11 10:12:58 [notice] 1#1: start worker process 29
2024/12/11 10:12:58 [notice] 1#1: start worker process 30
2024/12/11 10:12:58 [notice] 1#1: start worker process 31
2024/12/11 10:12:58 [notice] 1#1: start worker process 32
2024/12/11 10:12:58 [notice] 1#1: start worker process 33
2024/12/11 10:12:58 [notice] 1#1: start worker process 34
2024/12/11 10:12:58 [notice] 1#1: start worker process 35
2024/12/11 10:12:58 [notice] 1#1: start worker process 36
2024/12/11 10:12:58 [notice] 1#1: start worker process 37
2024/12/11 10:12:58 [notice] 1#1: start worker process 38
2024/12/11 10:12:58 [notice] 1#1: start worker process 39
2024/12/11 10:12:58 [notice] 1#1: start worker process 40
2024/12/11 10:12:58 [notice] 1#1: start worker process 41
2024/12/11 10:12:58 [notice] 1#1: start worker process 42
2024/12/11 10:12:58 [notice] 1#1: start worker process 43
2024/12/11 10:12:58 [notice] 1#1: start worker process 44
2024/12/11 10:12:58 [notice] 1#1: start worker process 45
2024/12/11 10:12:58 [notice] 1#1: start worker process 46
2024/12/11 10:12:58 [notice] 1#1: start worker process 47
2024/12/11 10:12:58 [notice] 1#1: start worker process 48
```
```
tom@Debian:~$ dk inspect 2d
[
    {
        "Id": "2dc20e0fe7dfee0205f16434ce655c6740124b30b961824852016acbfd03f152",
        "Created": "2024-12-11T10:12:58.548708728Z",
        "Path": "/docker-entrypoint.sh",
        "Args": [
            "nginx",
            "-g",
            "daemon off;"
        ],
        "State": {
            "Status": "running",
            "Running": true,
            "Paused": false,
            "Restarting": false,
            "OOMKilled": false,
            "Dead": false,
            "Pid": 8835,
            "ExitCode": 0,
            "Error": "",
            "StartedAt": "2024-12-11T10:12:58.668560495Z",
            "FinishedAt": "0001-01-01T00:00:00Z"
        },
        "Image": "sha256:66f8bdd3810c96dc5c28aec39583af731b34a2cd99471530f53c8794ed5b423e",
        "ResolvConfPath": "/var/lib/docker/containers/2dc20e0fe7dfee0205f16434ce655c6740124b30b961824852016acbfd03f152/resolv.conf",
        "HostnamePath": "/var/lib/docker/containers/2dc20e0fe7dfee0205f16434ce655c6740124b30b961824852016acbfd03f152/hostname",
        "HostsPath": "/var/lib/docker/containers/2dc20e0fe7dfee0205f16434ce655c6740124b30b961824852016acbfd03f152/hosts",
        "LogPath": "/var/lib/docker/containers/2dc20e0fe7dfee0205f16434ce655c6740124b30b961824852016acbfd03f152/2dc20e0fe7dfee0205f16434ce655c6740124b30b961824852016acbfd03f152-json.log",
        "Name": "/musing_hodgkin",
        "RestartCount": 0,
        "Driver": "overlay2",
        "Platform": "linux",
        "MountLabel": "",
        "ProcessLabel": "",
        "AppArmorProfile": "docker-default",
        "ExecIDs": null,
        "HostConfig": {
            "Binds": null,
            "ContainerIDFile": "",
            "LogConfig": {
                "Type": "json-file",
                "Config": {}
            },
            "NetworkMode": "bridge",
            "PortBindings": {
                "80/tcp": [
                    {
                        "HostIp": "",
                        "HostPort": "9999"
                    }
                ]
            },
            "RestartPolicy": {
                "Name": "no",
                "MaximumRetryCount": 0
            },
            "AutoRemove": false,
            "VolumeDriver": "",
            "VolumesFrom": null,
            "ConsoleSize": [
                41,
                188
            ],
            "CapAdd": null,
            "CapDrop": null,
            "CgroupnsMode": "private",
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": null,
            "GroupAdd": null,
            "IpcMode": "private",
            "Cgroup": "",
            "Links": null,
            "OomScoreAdj": 0,
            "PidMode": "",
            "Privileged": false,
            "PublishAllPorts": false,
            "ReadonlyRootfs": false,
            "SecurityOpt": null,
            "UTSMode": "",
            "UsernsMode": "",
            "ShmSize": 67108864,
            "Runtime": "runc",
            "Isolation": "",
            "CpuShares": 0,
            "Memory": 0,
            "NanoCpus": 0,
            "CgroupParent": "",
            "BlkioWeight": 0,
            "BlkioWeightDevice": [],
            "BlkioDeviceReadBps": [],
            "BlkioDeviceWriteBps": [],
            "BlkioDeviceReadIOps": [],
            "BlkioDeviceWriteIOps": [],
            "CpuPeriod": 0,
            "CpuQuota": 0,
            "CpuRealtimePeriod": 0,
            "CpuRealtimeRuntime": 0,
            "CpusetCpus": "",
            "CpusetMems": "",
            "Devices": [],
            "DeviceCgroupRules": null,
            "DeviceRequests": null,
            "MemoryReservation": 0,
            "MemorySwap": 0,
            "MemorySwappiness": null,
            "OomKillDisable": null,
            "PidsLimit": null,
            "Ulimits": [],
            "CpuCount": 0,
            "CpuPercent": 0,
            "IOMaximumIOps": 0,
            "IOMaximumBandwidth": 0,
            "MaskedPaths": [
                "/proc/asound",
                "/proc/acpi",
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/timer_list",
                "/proc/timer_stats",
                "/proc/sched_debug",
                "/proc/scsi",
                "/sys/firmware",
                "/sys/devices/virtual/powercap"
            ],
            "ReadonlyPaths": [
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger"
            ]
        },
        "GraphDriver": {
            "Data": {
                "LowerDir": "/var/lib/docker/overlay2/9eb632b6ad7c7a010dcac3efde3ef21ac563f0552050783261d0918bcb86e1e2-init/diff:/var/lib/docker/overlay2/1e6bb3390d62d7a8b248277e3fc609f37f9eb16ba6c8ca58b6aafcccac8dd95d/diff:/var/lib/docker/overlay2/587e4593891f8d7637c8695ef0357e5fc3cc8c34b2f182f6c6682a7efec9a268/diff:/var/lib/docker/overlay2/4dc2ffd12fa60dc5593e6aeaef2a14f0f722ea5aa2427b3dbda14f5dedfbaa1d/diff:/var/lib/docker/overlay2/f63e600f0f48292088b0f0db1bab1253ba4bab0f928c1f5db3ec39c57c4034e5/diff:/var/lib/docker/overlay2/2923f297c2d519aafaae392e31486bbbe0d6453a5a88942dfe4556b7a5d6be98/diff:/var/lib/docker/overlay2/240ef3d71eccdc5b9d07dd9f08b7ca4ada9e6785b286bb206d855bbdfeff216d/diff:/var/lib/docker/overlay2/7d351a148f43c3caf7854a336abe973c8187363b82b8d7a647d5117121376a8b/diff",
                "MergedDir": "/var/lib/docker/overlay2/9eb632b6ad7c7a010dcac3efde3ef21ac563f0552050783261d0918bcb86e1e2/merged",
                "UpperDir": "/var/lib/docker/overlay2/9eb632b6ad7c7a010dcac3efde3ef21ac563f0552050783261d0918bcb86e1e2/diff",
                "WorkDir": "/var/lib/docker/overlay2/9eb632b6ad7c7a010dcac3efde3ef21ac563f0552050783261d0918bcb86e1e2/work"
            },
            "Name": "overlay2"
        },
        "Mounts": [],
        "Config": {
            "Hostname": "2dc20e0fe7df",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "ExposedPorts": {
                "80/tcp": {}
            },
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NGINX_VERSION=1.27.3",
                "NJS_VERSION=0.8.7",
                "NJS_RELEASE=1~bookworm",
                "PKG_RELEASE=1~bookworm",
                "DYNPKG_RELEASE=1~bookworm"
            ],
            "Cmd": [
                "nginx",
                "-g",
                "daemon off;"
            ],
            "Image": "nginx",
            "Volumes": null,
            "WorkingDir": "",
            "Entrypoint": [
                "/docker-entrypoint.sh"
            ],
            "OnBuild": null,
            "Labels": {
                "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>"
            },
            "StopSignal": "SIGQUIT"
        },
        "NetworkSettings": {
            "Bridge": "",
            "SandboxID": "c4ce09f9d8f5b18f32209fdda072cd8ffef4195df4de51e6dc4b2e40b417b610",
            "SandboxKey": "/var/run/docker/netns/c4ce09f9d8f5",
            "Ports": {
                "80/tcp": [
                    {
                        "HostIp": "0.0.0.0",
                        "HostPort": "9999"
                    },
                    {
                        "HostIp": "::",
                        "HostPort": "9999"
                    }
                ]
            },
            "HairpinMode": false,
            "LinkLocalIPv6Address": "",
            "LinkLocalIPv6PrefixLen": 0,
            "SecondaryIPAddresses": null,
            "SecondaryIPv6Addresses": null,
            "EndpointID": "ec49901b71b2b8d14a151b79700d755469cb8c76cd21287916ce1d589d6ed40e",
            "Gateway": "172.17.0.1",
            "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0,
            "IPAddress": "172.17.0.2",
            "IPPrefixLen": 16,
            "IPv6Gateway": "",
            "MacAddress": "02:42:ac:11:00:02",
            "Networks": {
                "bridge": {
                    "IPAMConfig": null,
                    "Links": null,
                    "Aliases": null,
                    "MacAddress": "02:42:ac:11:00:02",
                    "DriverOpts": null,
                    "NetworkID": "f052aebed7d8117c7baff80a980db58077fc8e1d068201b6f5d53654787fa24c",
                    "EndpointID": "ec49901b71b2b8d14a151b79700d755469cb8c76cd21287916ce1d589d6ed40e",
                    "Gateway": "172.17.0.1",
                    "IPAddress": "172.17.0.2",
                    "IPPrefixLen": 16,
                    "IPv6Gateway": "",
                    "GlobalIPv6Address": "",
                    "GlobalIPv6PrefixLen": 0,
                    "DNSNames": null
                }
            }
        }
    }
]

```

```
tom@Debian:~$ sudo ss -lnpt
State             Recv-Q            Send-Q                       Local Address:Port                         Peer Address:Port            Process                                            
LISTEN            0                 128                              127.0.0.1:631                               0.0.0.0:*                users:(("cupsd",pid=980,fd=7))                    
🌞LISTEN            0                 4096                               0.0.0.0:9999                              0.0.0.0:*                users:(("docker-proxy",pid=8748,fd=4))            
LISTEN            0                 50                                       *:1716                                    *:*                users:(("kdeconnectd",pid=1824,fd=20))            
🌞LISTEN            0                 4096                                  [::]:9999                                 [::]:*                users:(("docker-proxy",pid=8765,fd=4))            
LISTEN            0                 128                                  [::1]:631                                  [::]:*                users:(("cupsd",pid=980,fd=6))       
```
```
tom@Debian:~$ sudo iptables -A INPUT -p tcp --dport 9999 -j ACCEPT
```

```
tom@Debian:~$ curl http://10.33.73.72:9999
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

🌞 **On va ajouter un site Web au conteneur NGINX**
```
tom@Debian:~/nginx$ sudo cat index.html 
<h1>MEOOOW</h1>
```
```
tom@Debian:~/nginx$ sudo cat site_nul.conf 
server {
    listen        8080;

    location / {
        root /var/www/html;
    }
}
```
```
tom@Debian:~/nginx$ docker run -d -p 9999:8080 \
-v /home/tom/nginx/index.html:/var/www/html/index.html \
-v /home/tom/nginx/site_nul.conf:/etc/nginx/conf.d/site_nul.conf \
nginx
a010c61d8a3961fc37d7d1b61eeb13bc3c12f846e27dd8bad440678a496597f6
tom@Debian:~/nginx$ curl http://localhost:9999
<h1>MEOOOW</h1>

```
🌞 **Visitons**

- vérifier que le conteneur est actif
```
tom@Debian:~/nginx$ dk ps
CONTAINER ID   IMAGE     COMMAND                  CREATED         STATUS         PORTS                                                 NAMES
a010c61d8a39   nginx     "/docker-entrypoint.…"   2 minutes ago   Up 2 minutes   80/tcp, 0.0.0.0:9999->8080/tcp, [::]:9999->8080/tcp   boring_hellman

```

## 5. Un deuxième conteneur en vif


🌞 **Lance un conteneur Python, avec un shell**
```
tom@Debian:~$ dk run -it python bash
Unable to find image 'python:latest' locally
latest: Pulling from library/python
fdf894e782a2: Pull complete 
5bd71677db44: Pull complete 
551df7f94f9c: Pull complete 
ce82e98d553d: Pull complete 
5f0e19c475d6: Pull complete 
abab87fa45d0: Pull complete 
2ac2596c631f: Pull complete 
Digest: sha256:220d07595f288567bbf07883576f6591dad77d824dce74f0c73850e129fa1f46
Status: Downloaded newer image for python:latest
root@ecc4639d465b:/# 
```

🌞 **Installe des libs Python**
```
root@ecc4639d465b:/# python
Python 3.13.1 (main, Dec  4 2024, 20:40:27) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import aiohttp
>>> import aioconsole

```

# II. Images

- [II. Images](#ii-images)
  - [1. Images publiques](#1-images-publiques)
  - [2. Construire une image](#2-construire-une-image)

## 1. Images publiques

🌞 **Récupérez des images**
```
tom@Debian:~$ dk images
REPOSITORY           TAG       IMAGE ID       CREATED         SIZE
linuxserver/wikijs   latest    863e49d2e56c   4 days ago      465MB
python               latest    3ca4060004b1   7 days ago      1.02GB
python               3.11      342f2c43d207   7 days ago      1.01GB
nginx                latest    66f8bdd3810c   2 weeks ago     192MB
wordpress            latest    c89b40a25cd1   2 weeks ago     700MB
mysql                5.7       5107333e08a8   12 months ago   501MB

```


🌞 **Lancez un conteneur à partir de l'image Python**
```
tom@Debian:~$ dk run -it python:3.11 bash
root@971e637c457e:/# python --version
Python 3.11.11
root@971e637c457e:/# python
Python 3.11.11 (main, Dec  4 2024, 20:38:25) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print("Hello, Python!")
Hello, Python!
>>> exit
Use exit()
```


## 2. Construire une image
🌞 **Ecrire un Dockerfile pour une image qui héberge une application Python**
🌞 **Build l'image**
```
tom@Debian:~/python_app_build$ docker build -t python-emoji-app .                         
[+] Building 23.8s (10/10) FINISHED                                                                                                                                          docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                   0.0s
 => => transferring dockerfile: 204B                                                                                                                                                   0.0s
 => [internal] load metadata for docker.io/library/debian:bullseye-slim                                                                                                                1.3s
 => [auth] library/debian:pull token for registry-1.docker.io                                                                                                                          0.0s
 => [internal] load .dockerignore                                                                                                                                                      0.0s
 => => transferring context: 2B                                                                                                                                                        0.0s
 => [1/4] FROM docker.io/library/debian:bullseye-slim@sha256:8118d0da5204dcc2f648d416b4c25f97255a823797aeb17495a01f2eb9c1b487                                                          1.4s
 => => resolve docker.io/library/debian:bullseye-slim@sha256:8118d0da5204dcc2f648d416b4c25f97255a823797aeb17495a01f2eb9c1b487                                                          0.0s
 => => sha256:8118d0da5204dcc2f648d416b4c25f97255a823797aeb17495a01f2eb9c1b487 4.54kB / 4.54kB                                                                                         0.0s
 => => sha256:43112fc2ced1dc71d4c92a1e42c3f831a2d5840ffa4d9fcd37802cd0594c1edf 1.02kB / 1.02kB                                                                                         0.0s
 => => sha256:4546fbfb0f90cb90fdbec49099cd4801600f8c92d3908b37529a930316016ed3 453B / 453B                                                                                             0.0s
 => => sha256:69fb10dc82f9580a647bd4638e741b2338cb8e2575d2be6f0bacfcada936a617 30.25MB / 30.25MB                                                                                       0.8s
 => => extracting sha256:69fb10dc82f9580a647bd4638e741b2338cb8e2575d2be6f0bacfcada936a617                                                                                              0.5s
 => [internal] load build context                                                                                                                                                      0.0s
 => => transferring context: 138B                                                                                                                                                      0.0s
 => [2/4] RUN apt-get update && apt-get install -y python3 python3-pip                                                                                                                19.3s
 => [3/4] RUN pip3 install emoji                                                                                                                                                       1.1s 
 => [4/4] COPY app.py /app.py                                                                                                                                                          0.0s 
 => exporting to image                                                                                                                                                                 0.7s 
 => => exporting layers                                                                                                                                                                0.7s 
 => => writing image sha256:b0adf5b76af6d62f2b42131cd0aec8f927a166f639d99c6165166b7e97e77fbe                                                                                           0.0s 
 => => naming to docker.io/library/python-emoji-app                                                                                                                                    0.0s 
tom@Debian:~/python_app_build$ docker images
REPOSITORY           TAG       IMAGE ID       CREATED         SIZE
python-emoji-app     latest    b0adf5b76af6   8 seconds ago   442MB
linuxserver/wikijs   latest    863e49d2e56c   4 days ago      465MB
python               latest    3ca4060004b1   7 days ago      1.02GB
python               3.11      342f2c43d207   7 days ago      1.01GB
nginx                latest    66f8bdd3810c   2 weeks ago     192MB
wordpress            latest    c89b40a25cd1   2 weeks ago     700MB
mysql                5.7       5107333e08a8   12 months ago   501MB
tom@Debian:~/python_app_build$ sudo cat 
app.py      Dockerfile  
tom@Debian:~/python_app_build$ sudo cat Dockerfile 
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install emoji
COPY app.py /app.py
ENTRYPOINT ["python3", "/app.py"]

```
🌞 **Lancer l'image**
```
tom@Debian:~/python_app_build$ docker run python-emoji-app
Cet exemple d'application est vraiment naze 👎

```
# III. Docker compose
🌞 **Créez un fichier `docker-compose.yml`**
```
version: "3"

services:
  conteneur_nul:
    image: debian
    entrypoint: sleep 9999
  conteneur_flopesque:
    image: debian
    entrypoint: sleep 9999

```
🌞 **Lancez les deux conteneurs** avec `docker compose`
```
tom@Debian:~/compose_test$ dk compose up -d
WARN[0000] /home/tom/compose_test/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
[+] Running 3/3
 ✔ conteneur_nul Pulled                                                                                                                                                                2.4s 
 ✔ conteneur_flopesque Pulled                                                                                                                                                          2.4s 
   ✔ fdf894e782a2 Already exists                                                                                                                                                       0.0s 
[+] Running 3/3
 ✔ Network compose_test_default                  Created                                                                                                                               0.2s 
 ✔ Container compose_test-conteneur_nul-1        Started                                                                                                                               0.4s 
 ✔ Container compose_test-conteneur_flopesque-1  Started                                                                                                                               0.4s 
tom@Debian:~/compose_test$ 


```

🌞 **Vérifier que les deux conteneurs tournent**
```
tom@Debian:~/compose_test$ docker compose ps
WARN[0000] /home/tom/compose_test/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
NAME                                 IMAGE     COMMAND        SERVICE               CREATED              STATUS              PORTS
compose_test-conteneur_flopesque-1   debian    "sleep 9999"   conteneur_flopesque   About a minute ago   Up About a minute   
compose_test-conteneur_nul-1         debian    "sleep 9999"   conteneur_nul         About a minute ago   Up About a minute 
```



🌞 **Pop un shell dans le conteneur `conteneur_nul`**

```

```





