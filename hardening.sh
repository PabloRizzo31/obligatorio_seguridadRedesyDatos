#!/bin/bash

# Este script endurece una imagen de Debian 12
# basándose en los CIS Benchmarks L1 y en los requerimientos del módulo SCA de Wazuh.

# Asegúrate de que el script se ejecuta como root
if [[ $EUID -ne 0 ]]; then
    echo "Este script debe ser ejecutado como root."
    exit 1
fi

## Requerimiento 1: Firewall local (nftables)
# ---------------------------------
echo "Configurando el firewall local con nftables..."

# Instala nftables si no está presente
apt-get update && apt-get install -y nftables

# Limpia cualquier configuración previa de nftables
nft flush ruleset

# Define la tabla 'filter' para IPv4
cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

# Elimina todas las reglas existentes
flush ruleset

table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Permite conexiones de bucle de retorno (loopback)
        iif "lo" accept

        # Permite conexiones ya establecidas y relacionadas
        ct state established,related accept

        # Permite tráfico entrante de SSH
        tcp dport 22 ct state new accept

        # Permite el tráfico entrante del SIEM (Wazuh)
        tcp dport 1514 ct state new accept
        tcp dport 1515 ct state new accept
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        # La política de salida 'accept' ya está configurada,
        # lo que permite conexiones salientes a Internet.
    }
}
EOF

# Aplica las reglas y habilita el servicio de nftables para que persista
nft -f /etc/nftables.conf
systemctl enable nftables
systemctl start nftables

# Bloquea los protocolos de red no utilizados según CIS 3.5
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

# Configuración de los parámetros del kernel para auditd
# Se asegura que la auditoría está habilitada al arrancar el sistema
sed -i 's/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1"/' /etc/default/grub
update-grub

# Borrar reglas existentes
auditctl -D

# Agregar reglas de auditoría de archivos de configuración críticos
echo "-w /etc/group -p wa -k identity_changes" > /etc/audit/rules.d/identity.rules
echo "-w /etc/passwd -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/gshadow -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/shadow -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/security/opasswd -p wa -k identity_changes" >> /etc/audit/rules.d/identity.rules

# Agregar reglas para monitoreo de comandos privilegiados
echo "-w /usr/bin/sudo -p x -k privileged_command" > /etc/audit/rules.d/privileged.rules
echo "-w /usr/bin/su -p x -k privileged_command" >> /etc/audit/rules.d/privileged.rules

# Agregar reglas para cambios en la configuración de red
echo "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules

# Configuración de retención de logs de auditd
sed -i 's/^max_log_file =.*/max_log_file = 50/' /etc/audit/auditd.conf
sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action =.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

# Configuración de inmutabilidad de las reglas (al final)
echo "-e 2" > /etc/audit/rules.d/99-finalize.rules

# Iniciar y habilitar el servicio
systemctl start auditd
systemctl enable auditd
systemctl restart auditd


## Requerimiento 3: Acceso administrativo seguro (SSH)
# ---------------------------------
echo "Asegurando el acceso SSH..."
# Crear una copia de seguridad
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Hardening de configuraciones de sshd_config
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

# Reiniciar el servicio SSH para aplicar los cambios
systemctl restart sshd

## Requerimiento 4: Integración con el SIEM
# ---------------------------------
echo "Instalando y configurando el agente del SIEM..."
WAZUH_MANAGER="192.168.1.10"
VERSION="4.12.0"
URL="https://packages.wazuh.com/${VERSION}/apt/pool/main/w/wazuh-agent/wazuh-agent_${VERSION}-1_amd64.deb"

# Descargar y verificar si la descarga fue exitosa
if wget -O wazuh-agent.deb $URL; then
    sudo WAZUH_MANAGER=$WAZUH_MANAGER dpkg -i ./wazuh-agent.deb
    
    # Iniciar y habilitar el agente
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    echo "Agente de Wazuh instalado y configurado."
else
    echo "Error: No se pudo descargar el paquete de Wazuh." >&2
    exit 1
fi

echo "Proceso de hardening completado."