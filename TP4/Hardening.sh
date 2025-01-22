#!/bin/bash

# Script de durcissement pour machines Linux
# Usage: sudo ./Hardening.sh

# Vérification que le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root"
    exit 1
fi

# Configuration du kernel
configure_kernel() {
    echo "Configuration du kernel..."
    
    # Création/modification du fichier de configuration sysctl
    cat > /etc/sysctl.d/99-hardening.conf << EOF
# Protection contre les attaques de type Buffer Overflow
kernel.randomize_va_space = 2

# Désactivation du forwarding IPv4/IPv6
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Protection contre les attaques de type SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Désactivation des pings (ICMP)
net.ipv4.icmp_echo_ignore_all = 1

# Protection contre les attaques de type MITM
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Protection contre le source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF

    # Application des paramètres
    sysctl -p /etc/sysctl.d/99-hardening.conf
}

# Configuration de SSH
configure_ssh() {
    echo "Configuration de SSH..."
    
    # Sauvegarde du fichier de configuration SSH original
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Configuration SSH sécurisée
    cat > /etc/ssh/sshd_config << EOF
# Désactivation de la connexion root
PermitRootLogin no

# Utilisation de la version 2 du protocole uniquement
Protocol 2

# Authentification par clé uniquement
PasswordAuthentication no
PubkeyAuthentication yes

# Temps maximum pour s'authentifier
LoginGraceTime 30

# Nombre maximum de tentatives de connexion
MaxAuthTries 3

# Désactivation des tunnels X11
X11Forwarding no

# Affichage de la bannière
Banner /etc/ssh/banner

# Temps d'inactivité avant déconnexion
ClientAliveInterval 300
ClientAliveCountMax 0

# Interface et port d'écoute
Port 22
ListenAddress 0.0.0.0
EOF

    # Création d'une bannière SSH
    echo "Accès restreint - Connexions surveillées et enregistrées" > /etc/ssh/banner
    
    # Redémarrage du service SSH
    systemctl restart sshd
}

# Configuration de NGINX
configure_nginx() {
    echo "Configuration de NGINX..."
    
    # Installation de NGINX si non présent
    if ! command -v nginx &> /dev/null; then
        dnf install -y nginx
    fi
    
    # Configuration NGINX sécurisée
    cat > /etc/nginx/nginx.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    # Masquer la version de NGINX
    server_tokens off;
    
    # Configuration des types MIME
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Configuration des logs
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    # Configuration SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # Protection contre les attaques XSS
    add_header X-XSS-Protection "1; mode=block";
    
    # Protection contre le clickjacking
    add_header X-Frame-Options "SAMEORIGIN";
    
    # Protection contre le MIME-sniffing
    add_header X-Content-Type-Options nosniff;
    
    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Redémarrage de NGINX
    systemctl restart nginx
}

# Installation et configuration de fail2ban
install_fail2ban() {
    echo "Installation et configuration de fail2ban..."
    
    # Installation de fail2ban
    dnf install -y fail2ban
    
    # Configuration de fail2ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
EOF

    # Démarrage de fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
}

# Installation et configuration de AIDE
install_aide() {
    echo "Installation et configuration de AIDE..."
    
    # Installation de AIDE
    dnf install -y aide
    
    # Initialisation de la base de données AIDE
    aide --init
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    
    # Création d'un service systemd pour les vérifications quotidiennes
    cat > /etc/systemd/system/aide-check.service << EOF
[Unit]
Description=AIDE Check

[Service]
Type=simple
ExecStart=/usr/sbin/aide --check

[Install]
WantedBy=multi-user.target
EOF

    # Création d'un timer systemd
    cat > /etc/systemd/system/aide-check.timer << EOF
[Unit]
Description=Daily AIDE check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Activation du timer
    systemctl enable aide-check.timer
    systemctl start aide-check.timer
}

# Configuration de sudo
configure_sudo() {
    echo "Configuration de sudo..."
    
    # Configuration de sudo
    cat > /etc/sudoers.d/hardening << EOF
Defaults        use_pty
Defaults        logfile="/var/log/sudo.log"
Defaults        log_input,log_output
Defaults        requiretty
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF

    chmod 440 /etc/sudoers.d/hardening
}

# Fonction principale
main() {
    echo "Début du processus de durcissement..."
    
    configure_kernel
    configure_ssh
    configure_nginx
    install_fail2ban
    install_aide
    configure_sudo
    
    echo "Processus de durcissement terminé."
}

# Exécution du script
main
