#!/bin/bash

# Este script endurece una imagen de Debian 12
# basándose en los CIS Benchmarks L1 y en los requerimientos del módulo SCA de Wazuh.

if [[ $EUID -ne 0 ]]; then
    echo "Este script debe ser ejecutado como root."
    exit 1
fi

# Sincronizar la hora del sistema para evitar errores de certificado en apt
echo "Sincronizando la hora del sistema..."
apt-get update -y
apt-get install -y ntpdate
ntpdate pool.ntp.org
hwclock --systohc

# Configurar locale para evitar advertencias de Perl
echo "Configurando locale del sistema..."
locale-gen es_UY.UTF-8 en_US.UTF-8
update-locale LANG=en_US.UTF-8

# A partir de aquí, el script sigue la lógica anterior
## Requerimiento 1: Firewall local (nftables)
# ---------------------------------
echo "Configurando el firewall local con nftables..."

apt-get update && apt-get install -y nftables

nft flush ruleset

cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

flush ruleset

table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept
        tcp dport 22 ct state new accept
        tcp dport 1514 ct state new accept
        tcp dport 1515 ct state new accept
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

nft -f /etc/nftables.conf
systemctl enable nftables
systemctl start nftables

echo "Deshabilitando protocolos de red no utilizados..."
echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf
modprobe -r dccp sctp rds tipc 2>/dev/null


## Requerimiento 2: Auditoría del sistema (auditd)
# ---------------------------------
echo "Configurando la auditoría del sistema con auditd..."
apt-get update && apt-get install -y auditd audispd-plugins

sed -i 's/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1"/' /etc/default/grub
update-grub

auditctl -D

echo "-w /etc/group -p wa -k identity_changes" > /etc/audit/rules.d/identity.rules
echo "-w /etc/passwd -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/gshadow -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/shadow -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/security/opasswd -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules
echo "-w /usr/bin/sudo -p x -k privileged_command" > /etc/audit/rules.d/privileged.rules
echo "-w /usr/bin/su -p x -k privileged_command" >> /etc/audit/rules.d/privileged.rules
echo "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules

sed -i 's/^max_log_file =.*/max_log_file = 50/' /etc/audit/auditd.conf
sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action =.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

echo "-e 2" > /etc/audit/rules.d/99-finalize.rules

systemctl start auditd
systemctl enable auditd
systemctl restart auditd


## Requerimiento 3: Acceso administrativo seguro (SSH)
# ---------------------------------
echo "Asegurando el acceso SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config
sed -i 's/^#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
sed -i 's/^#LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
sed -i 's/^#MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config
sed -i 's/^#MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config
sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
systemctl restart sshd

## Requerimiento 4: Integración con el SIEM
# ---------------------------------
echo "Instalando y configurando el agente del SIEM..."
WAZUH_MANAGER="192.168.1.10"
VERSION="4.12.0-1"

# Reemplazar por una URL de descarga más confiable o genérica
AGENT_DEB="wazuh-agent_"$VERSION"_amd64.deb"
URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_"$VERSION"_amd64.deb"

# Intentar descargar el agente con wget y manejar el error
if wget -O "$AGENT_DEB" "$URL"; then
    echo "Paquete de Wazuh descargado correctamente."
    dpkg -i "./$AGENT_DEB"
    # Configurar el agente para apuntar al manager de Wazuh
    if [ -f "/var/ossec/etc/ossec.conf" ]; then
        sed -i "s/<manager_ip>/\$WAZUH_MANAGER/" /var/ossec/etc/ossec.conf
    fi
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    echo "Agente de Wazuh instalado y configurado."
else
    echo "Error: No se pudo descargar el paquete de Wazuh. Verifique la URL y la conectividad." >&2
    exit 1
fi

echo "Proceso de hardening completado."