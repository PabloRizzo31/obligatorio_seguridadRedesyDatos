#!/usr/bin/env bash
set -euo pipefail


## Instala y configura Mod Security 
#y todo lo necesario para activarlo 

# Si luego se precisa activar el modo bloqueo, ejecutar el script con:
# sudo MODE=blocking PARANOIA=2 ./instalall.sh

# === Parámetros ajustables ===
# detection|blocking
MODE="${MODE:-detection}"   # detection => SecRuleEngine DetectionOnly; blocking => On
PARANOIA="${PARANOIA:-1}"   # 1..4 (más alto = más estricto)
CRS_DIR="/etc/modsecurity/owasp-crs"
MODSEC_CONF="/etc/modsecurity/modsecurity.conf"
APACHE_MODSEC_CONF="/etc/apache2/conf-available/mod-security.conf"
APACHE_FQDN_CONF="/etc/apache2/conf-available/fqdn.conf"
AUDIT_DIR="/var/log/modsecurity"
AUDIT_LOG="${AUDIT_DIR}/audit.log"

export DEBIAN_FRONTEND=noninteractive

echo "[1/9] APT: update + paquetes base..."
apt-get update -y
apt-get install -y --no-install-recommends \
  apache2 \
  libapache2-mod-security2 \
  git ca-certificates locales

# (Opcional) locales para evitar warnings perl
if ! locale -a | grep -qi 'en_US\.utf8'; then
  locale-gen en_US.UTF-8 es_UY.UTF-8 || true
fi
if ! grep -q '^LANG=' /etc/default/locale 2>/dev/null; then
  printf "LANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8\n" > /etc/default/locale
fi
export LANG=${LANG:-en_US.UTF-8}
export LC_ALL=${LC_ALL:-en_US.UTF-8}

echo "[2/9] Estructura y backups..."
mkdir -p /etc/modsecurity
mkdir -p "$AUDIT_DIR"
# Propietario y permisos para que Apache (www-data) pueda escribir el audit log
chown www-data:www-data "$AUDIT_DIR" || true
chmod 750 "$AUDIT_DIR" || true
: > "$AUDIT_LOG"
chown www-data:www-data "$AUDIT_LOG"
chmod 640 "$AUDIT_LOG"

# Copiar modsecurity.conf base si no existe y hacer backup 1 vez
if [[ -f /etc/modsecurity/modsecurity.conf-recommended && ! -f "$MODSEC_CONF" ]]; then
  cp /etc/modsecurity/modsecurity.conf-recommended "$MODSEC_CONF"
fi
if [[ -f "$MODSEC_CONF" && ! -f "${MODSEC_CONF}.bak" ]]; then
  cp "$MODSEC_CONF" "${MODSEC_CONF}.bak"
fi

echo "[3/9] Configuración base de ModSecurity..."
# Modo del motor
if [[ "$MODE" == "blocking" ]]; then
  sed -i 's/^\s*SecRuleEngine\s\+.*/SecRuleEngine On/' "$MODSEC_CONF"
else
  sed -i 's/^\s*SecRuleEngine\s\+.*/SecRuleEngine DetectionOnly/' "$MODSEC_CONF"
fi

# Asegurar directivas clave
grep -q '^\s*SecAuditEngine'    "$MODSEC_CONF" || echo 'SecAuditEngine RelevantOnly' >> "$MODSEC_CONF"
grep -q '^\s*SecAuditLogParts'  "$MODSEC_CONF" || echo 'SecAuditLogParts ABCEFKZ'   >> "$MODSEC_CONF"
grep -q '^\s*SecAuditLogType'   "$MODSEC_CONF" || echo 'SecAuditLogType Serial'     >> "$MODSEC_CONF"
grep -q '^\s*SecStatusEngine'   "$MODSEC_CONF" || echo 'SecStatusEngine On'         >> "$MODSEC_CONF"

# Forzar el path del audit log a /var/log/modsecurity/audit.log (reemplaza cualquiera previo)
if grep -q '^\s*SecAuditLog\s\+' "$MODSEC_CONF"; then
  sed -i "s|^\s*SecAuditLog\s\+.*|SecAuditLog ${AUDIT_LOG}|" "$MODSEC_CONF"
else
  echo "SecAuditLog ${AUDIT_LOG}" >> "$MODSEC_CONF"
fi

echo "[4/9] Desplegando OWASP CRS desde GitHub (evitando duplicados con paquete Debian)..."
# Si existe paquete modsecurity-crs, desinstalar para evitar doble carga
if dpkg -l | grep -q '^ii\s\+modsecurity-crs\s'; then
  apt-get remove -y modsecurity-crs || true
fi

# Clonar/actualizar CRS
if [[ -d "$CRS_DIR/.git" ]]; then
  git -C "$CRS_DIR" fetch --all --prune
  git -C "$CRS_DIR" reset --hard origin/v4.0/dev || git -C "$CRS_DIR" pull --rebase || true
else
  mkdir -p "$CRS_DIR"
  git clone --depth 1 --branch v4.0/dev https://github.com/coreruleset/coreruleset.git "$CRS_DIR" \
    || git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
fi

# crs-setup.conf
if [[ -f "$CRS_DIR/crs-setup.conf.example" && ! -f "$CRS_DIR/crs-setup.conf" ]]; then
  cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"
fi
# Nivel de paranoia
if grep -q '^\s*#\s*tx\.paranoia_level' "$CRS_DIR/crs-setup.conf"; then
  sed -i "s|^\s*#\s*tx\.paranoia_level\s*=.*|tx.paranoia_level=${PARANOIA}|" "$CRS_DIR/crs-setup.conf"
else
  sed -i "s|^\s*tx\.paranoia_level\s*=.*|tx.paranoia_level=${PARANOIA}|" "$CRS_DIR/crs-setup.conf" || true
fi

echo "[5/9] Config Apache: includes de CRS (sin incluir modsecurity.conf aquí)..."
cat > "$APACHE_MODSEC_CONF" <<'EOF'
<IfModule security2_module>
    # modsecurity.conf se incluye desde mods-available/security2.conf (IncludeOptional /etc/modsecurity/*.conf)
    # Incluir SOLO CRS aquí para evitar duplicados
    Include /etc/modsecurity/owasp-crs/crs-setup.conf
    Include /etc/modsecurity/owasp-crs/rules/*.conf
</IfModule>
EOF

echo "[6/9] ServerName global para evitar warning AH00558..."
echo "ServerName localhost" > "$APACHE_FQDN_CONF"

echo "[7/9] Habilitar módulo y configs..."
a2enmod security2 >/dev/null || true
a2enconf mod-security >/dev/null || true
a2enconf fqdn >/dev/null || true

echo "[8/9] Validar sintaxis..."
apachectl configtest

echo "[9/9] Recargar Apache..."
systemctl reload apache2

echo "✅ Listo: ModSecurity (${MODE}) + OWASP CRS (Paranoia=${PARANOIA}) en Debian 12"
echo "   Audit log: ${AUDIT_LOG}"
echo "   Para ver en vivo: tail -f ${AUDIT_LOG}"
echo "   Probar 403: curl -I 'http://localhost/?q=<script>alert(1)</script>'"



