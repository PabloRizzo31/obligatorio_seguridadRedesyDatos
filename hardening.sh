#!/bin/bash

# Este script endurece una imagen de Debian 
# basándose en los CIS Benchmarks L1 y en los requerimientos minimos
# del obligatorio

## Requerimiento 1: Firewall local
# ---------------------------------
echo "Configurando el firewall local con iptables..."
# Limpiar todas las reglas existentes y establecer políticas predeterminadas
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X

# Permitir tráfico de bucle de retorno (loopback)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir tráfico saliente de conexiones ya establecidas
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permitir tráfico saliente para servicios web y DNS
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT

# Permitir tráfico entrante SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# Permitir tráfico entrante para el agente de Wazuh
# El tráfico saliente ya está permitido por la política OUTPUT y la regla ESTABLISHED
iptables -A INPUT -p tcp --dport 1514 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 1515 -m state --state NEW,ESTABLISHED -j ACCEPT

# Guardar las reglas para que persistan
if [ -x "$(command -v iptables-save)" ]; then
    echo "Guardando reglas de iptables..."
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
fi


## Requerimiento 2: Auditoría del sistema
# ---------------------------------
echo "Configurando la auditoría del sistema con auditd..."
apt-get update && apt-get install -y auditd audispd-plugins

# Borrar reglas existentes
auditctl -D

# Agregar reglas CIS L1 para monitoreo de archivos críticos
auditctl -w /etc/passwd -p wa -k identity_changes
auditctl -w /etc/shadow -p wa -k identity_changes
auditctl -w /etc/group -p wa -k identity_changes
auditctl -w /etc/gshadow -p wa -k identity_changes
auditctl -w /etc/sudoers -p wa -k sudoers_changes
auditctl -w /etc/crontab -p wa -k cron_changes

# Monitoreo de comandos privilegiados
auditctl -w /usr/bin/sudo -p x -k privileged_command
auditctl -w /usr/bin/su -p x -k privileged_command

# Iniciar y habilitar el servicio
systemctl start auditd
systemctl enable auditd


## Requerimiento 3: Acceso administrativo seguro
# ---------------------------------
echo "Asegurando el acceso SSH..."
# Crear una copia de seguridad
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Deshabilitar inicio de sesión como root
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Deshabilitar autenticación por contraseña
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Asegurar protocolo 2
sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config

# Deshabilitar autenticación de host
sed -i 's/^HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config

# Reiniciar el servicio SSH
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