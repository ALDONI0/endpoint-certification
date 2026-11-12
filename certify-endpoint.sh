#!/usr/bin/env bash
# =============================================================================
#  certify-endpoint.sh
#  Certificación de endpoints Linux y macOS contra una línea base de seguridad.
#  Linux and macOS endpoint certification against a security baseline.
#
#  Uso / Usage:
#    sudo ./certify-endpoint.sh [-l es|en] [-o carpeta] [-a admin1,admin2]
#                               [-d dominio] [-b paquete1,paquete2] [-p perfil] [-A] [-h]
#
#    -l  Idioma del reporte (es predeterminado) / Report language
#    -o  Carpeta de salida (./reports) / Output folder
#    -a  Administradores autorizados, separados por comas / Allowed admins
#    -d  Dominio esperado (realm/AD) / Expected domain
#    -b  Software bloqueado, separado por comas / Blocked software
#    -p  Perfil: workstation (predeterminado) o server. En server el cifrado
#        de disco baja a severidad media / Profile: workstation or server
#    -A  Anonimizar el reporte antes de publicarlo / Anonymize the report
#
#  Códigos de salida / Exit codes:
#    0 certificado · 1 con observaciones · 2 no certificado · 3 error
#
#  Compatible con bash 3.2 (macOS) y bash 4/5 (Linux).
# =============================================================================

set -u

VERSION="1.0.0"
LANG_SEL="es"
OUT_DIR="./reports"
ALLOWED_ADMINS=""
EXPECTED_DOMAIN=""
BLOCKED_SW="anydesk,teamviewer,qbittorrent,transmission,utorrent,deluge,ultraviewer"
ANONYMIZE=0
PROFILE="workstation"
MIN_PASS_LEN=12
MAX_UPTIME_DAYS=14
MIN_FREE_PCT=15

usage() { sed -n '2,22p' "$0" | sed 's/^#  \{0,1\}//'; exit 0; }

while getopts "l:o:a:d:b:p:Ah" opt; do
  case "$opt" in
    l) LANG_SEL="$OPTARG" ;;
    o) OUT_DIR="$OPTARG" ;;
    a) ALLOWED_ADMINS="$OPTARG" ;;
    d) EXPECTED_DOMAIN="$OPTARG" ;;
    b) BLOCKED_SW="$OPTARG" ;;
    p) PROFILE="$OPTARG" ;;
    A) ANONYMIZE=1 ;;
    h|*) usage ;;
  esac
done
[ "$LANG_SEL" = "en" ] || LANG_SEL="es"
[ "$PROFILE" = "server" ] || PROFILE="workstation"

# ---------------------------------------------------------------- utilidades
t() { if [ "$LANG_SEL" = "en" ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

OS="$(uname -s)"
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
if [ "$OS" != "Linux" ] && [ "$OS" != "Darwin" ]; then
  echo "$(t 'Sistema no compatible. En Windows usa Invoke-EndpointCertification.ps1.' 'Unsupported OS. On Windows use Invoke-EndpointCertification.ps1.')" >&2
  exit 3
fi

if [ -t 1 ]; then C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_C=$'\033[36m'; C_M=$'\033[35m'; C_0=$'\033[0m'
else C_G=""; C_R=""; C_Y=""; C_C=""; C_M=""; C_0=""; fi

# Resultados en arreglos paralelos (bash 3.2 no tiene arreglos asociativos)
R_ID=(); R_CAT=(); R_SEV=(); R_STATUS=(); R_NAME=(); R_DETAIL=(); R_FIX=(); R_REF=()

status_label() {
  case "$1" in
    PASS) t "CUMPLE" "PASS" ;; FAIL) t "NO CUMPLE" "FAIL" ;; WARN) t "ADVERTENCIA" "WARNING" ;;
    INFO) printf 'INFO' ;; *) printf 'ERROR' ;;
  esac
}
sev_label() { case "$1" in High) t "Alta" "High" ;; Medium) t "Media" "Medium" ;; *) t "Baja" "Low" ;; esac; }
cat_label() {
  case "$1" in
    Security) t "Seguridad" "Security" ;; Patching) t "Parches" "Patching" ;; Accounts) t "Cuentas" "Accounts" ;;
    Network) t "Red" "Network" ;; System) t "Sistema" "System" ;; Software) printf 'Software' ;;
    Behavior) t "Hábitos de usuario" "User behavior" ;; Maintenance) t "Mantenimiento" "Maintenance" ;; *) t "Dominio" "Domain" ;;
  esac
}

# add_result ID CATEGORIA SEVERIDAD ESTADO NOMBRE DETALLE CORRECCION REFERENCIA
add_result() {
  R_ID+=("$1"); R_CAT+=("$2"); R_SEV+=("$3"); R_STATUS+=("$4"); R_NAME+=("$5"); R_DETAIL+=("$6")
  if [ "$4" = "PASS" ] || [ "$4" = "INFO" ]; then R_FIX+=(""); else R_FIX+=("$7"); fi
  R_REF+=("$8")
  local color
  case "$4" in PASS) color="$C_G" ;; FAIL) color="$C_R" ;; WARN) color="$C_Y" ;; ERROR) color="$C_M" ;; *) color="$C_C" ;; esac
  printf '  %s%-15s%s %-9s %s\n' "$color" "[$(status_label "$4")]" "$C_0" "$1" "$5"
}

need_root_detail() { t "Se requiere ejecutar con sudo para evaluar este control." "Run with sudo to evaluate this control."; }

# ---------------------------------------------------------------- controles
check_firewall() {
  local name fix status detail
  name="$(t 'Firewall activo' 'Firewall enabled')"
  if [ "$OS" = "Darwin" ]; then
    fix="$(t 'Ajustes del Sistema > Red > Firewall: activar.' 'System Settings > Network > Firewall: turn on.')"
    if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -qi 'enabled'; then
      status=PASS; detail="$(t 'Firewall de aplicaciones activo.' 'Application firewall enabled.')"
    else status=FAIL; detail="$(t 'Firewall de aplicaciones desactivado.' 'Application firewall disabled.')"; fi
  else
    fix="$(t 'Ubuntu: sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw enable' 'Ubuntu: sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw enable')"
    if have ufw && [ "$IS_ROOT" -eq 1 ] && ufw status 2>/dev/null | grep -qiE 'status: active|estado: activo'; then
      status=PASS; detail="$(t 'UFW activo.' 'UFW active.')"
    elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then
      status=PASS; detail="$(t 'firewalld en ejecución.' 'firewalld running.')"
    elif have nft && [ "$IS_ROOT" -eq 1 ] && [ "$(nft list ruleset 2>/dev/null | grep -c 'hook input')" -gt 0 ]; then
      status=PASS; detail="$(t 'Reglas nftables con cadena de entrada.' 'nftables ruleset with input chain.')"
    elif [ "$IS_ROOT" -eq 0 ]; then status=ERROR; detail="$(need_root_detail)"
    else status=FAIL; detail="$(t 'No se encontró un firewall activo (ufw, firewalld o nftables).' 'No active firewall found (ufw, firewalld or nftables).')"; fi
  fi
  add_result "SEC-01" Security High "$status" "$name" "$detail" "$fix" "CIS v8 4.5"
}

check_encryption() {
  local name fix status detail
  name="$(t 'Disco cifrado' 'Disk encrypted')"
  if [ "$OS" = "Darwin" ]; then
    fix="$(t 'Activa FileVault: sudo fdesetup enable' 'Enable FileVault: sudo fdesetup enable')"
    if fdesetup status 2>/dev/null | grep -q 'FileVault is On'; then status=PASS; detail="FileVault $(t 'activo.' 'on.')"
    else status=FAIL; detail="FileVault $(t 'desactivado.' 'off.')"; fi
  else
    fix="$(t 'Cifra el disco con LUKS (en Ubuntu se elige al instalar: Usar LVM con cifrado).' 'Encrypt with LUKS (Ubuntu installer: Use LVM with encryption).')"
    if have lsblk && lsblk -o TYPE 2>/dev/null | grep -q '^crypt'; then
      status=PASS; detail="$(t 'Volumen LUKS detectado.' 'LUKS volume detected.')"
    elif have lsblk; then
      status=FAIL; detail="$(t 'No se detectó ningún volumen cifrado (LUKS).' 'No encrypted (LUKS) volume detected.')"
    else status=ERROR; detail="$(t 'lsblk no está disponible.' 'lsblk is not available.')"; fi
  fi
  # En servidores de centro de datos la seguridad física compensa parcialmente
  local sev=High; [ "$PROFILE" = "server" ] && sev=Medium
  add_result "SEC-02" Security "$sev" "$status" "$name" "$detail" "$fix" "CIS v8 3.6"
}

check_antimalware() {
  local name fix status detail
  name="$(t 'Protección antimalware' 'Anti-malware protection')"
  fix="$(t 'Instala el antimalware corporativo (por ejemplo Microsoft Defender for Endpoint o ClamAV).' 'Install the corporate anti-malware (e.g. Defender for Endpoint or ClamAV).')"
  if [ "$OS" = "Darwin" ]; then
    if spctl --status 2>/dev/null | grep -q 'assessments enabled'; then
      status=PASS; detail="$(t 'Gatekeeper y XProtect activos.' 'Gatekeeper and XProtect enabled.')"
    else status=FAIL; detail="$(t 'Gatekeeper desactivado.' 'Gatekeeper disabled.')"; fi
  else
    if have mdatp; then status=PASS; detail="Microsoft Defender for Endpoint $(t 'instalado.' 'installed.')"
    elif have clamscan || have clamdscan; then status=PASS; detail="ClamAV $(t 'instalado.' 'installed.')"
    else status=WARN; detail="$(t 'No se encontró antimalware. En servidores puede ser aceptable si la política lo indica.' 'No anti-malware found. May be acceptable on servers per policy.')"; fi
  fi
  add_result "SEC-03" Security Medium "$status" "$name" "$detail" "$fix" "CIS v8 10.1"
}

check_updates() {
  local name fix status detail count sec
  name="$(t 'Actualizaciones pendientes' 'Pending updates')"
  if [ "$OS" = "Darwin" ]; then
    fix="$(t 'Instala las actualizaciones: softwareupdate -ia' 'Install updates: softwareupdate -ia')"
    if softwareupdate -l 2>&1 | grep -q 'No new software available'; then status=PASS; detail="$(t 'Sin actualizaciones pendientes.' 'No pending updates.')"
    else status=FAIL; detail="$(t 'Hay actualizaciones de macOS pendientes.' 'macOS updates are pending.')"; fi
  elif have apt; then
    fix="$(t 'Ejecuta: sudo apt update && sudo apt full-upgrade' 'Run: sudo apt update && sudo apt full-upgrade')"
    count=$(apt list --upgradable 2>/dev/null | grep -c 'upgradable')
    sec=$(apt list --upgradable 2>/dev/null | grep -c -- '-security')
    detail="$(t "Paquetes por actualizar: $count (de seguridad: $sec). Basado en la última ejecución de apt update." "Upgradable packages: $count (security: $sec). Based on the last apt update.")"
    if [ "$sec" -gt 0 ]; then status=FAIL; elif [ "$count" -gt 0 ]; then status=WARN; else status=PASS; fi
  elif have dnf; then
    fix="$(t 'Ejecuta: sudo dnf upgrade --security' 'Run: sudo dnf upgrade --security')"
    sec=$(dnf -q updateinfo list --security 2>/dev/null | grep -c . )
    detail="$(t "Avisos de seguridad pendientes: $sec." "Pending security advisories: $sec.")"
    if [ "$sec" -gt 0 ]; then status=FAIL; else status=PASS; fi
  else
    status=ERROR; fix=""; detail="$(t 'Gestor de paquetes no reconocido.' 'Unknown package manager.')"
  fi
  add_result "PAT-01" Patching High "$status" "$name" "$detail" "$fix" "CIS v8 7.3"
}

check_auto_updates() {
  local name fix status detail
  name="$(t 'Actualizaciones automáticas de seguridad' 'Automatic security updates')"
  if [ "$OS" = "Darwin" ]; then
    fix="$(t 'Ajustes del Sistema > General > Actualización de software > Actualizaciones automáticas.' 'System Settings > General > Software Update > Automatic updates.')"
    if [ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)" = "1" ]; then
      status=PASS; detail="$(t 'Respuestas de seguridad automáticas activas.' 'Automatic security responses enabled.')"
    else status=WARN; detail="$(t 'No se confirmó la instalación automática de parches críticos.' 'Automatic critical patch install not confirmed.')"; fi
  elif [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
    status=PASS; detail="unattended-upgrades $(t 'activo.' 'enabled.')"; fix=""
  elif have systemctl && systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
    status=PASS; detail="dnf-automatic $(t 'activo.' 'enabled.')"; fix=""
  else
    status=WARN; detail="$(t 'No hay actualizaciones automáticas configuradas.' 'No automatic updates configured.')"
    fix="$(t 'Ubuntu: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades' 'Ubuntu: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades')"
  fi
  add_result "PAT-02" Patching Medium "$status" "$name" "$detail" "$fix" "CIS v8 7.3"
}

check_reboot() {
  local status detail
  if [ -f /var/run/reboot-required ]; then status=WARN; detail="$(t 'El sistema pide reinicio para terminar de aplicar actualizaciones.' 'System requires a reboot to finish updates.')"
  else status=PASS; detail="$(t 'No hay reinicio pendiente.' 'No pending reboot.')"; fi
  add_result "PAT-03" Patching Medium "$status" "$(t 'Sin reinicio pendiente' 'No pending reboot')" "$detail" "$(t 'Reinicia el equipo.' 'Reboot the device.')" "CIS v8 7.3"
}

check_uid0() {
  local status detail users
  if [ "$OS" = "Darwin" ]; then users=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2==0{print $1}' | tr '\n' ' ')
  else users=$(awk -F: '($3==0){print $1}' /etc/passwd | tr '\n' ' '); fi
  users="${users% }"
  if [ "$users" = "root" ]; then status=PASS; detail="$(t 'Solo root tiene UID 0.' 'Only root has UID 0.')"
  else status=FAIL; detail="$(t "Cuentas con UID 0: $users" "Accounts with UID 0: $users")"; fi
  add_result "ACC-01" Accounts High "$status" "$(t 'Solo root con privilegios totales (UID 0)' 'Only root has UID 0')" "$detail" \
    "$(t 'Cambia el UID de las cuentas extra o elimínalas.' 'Change the UID of extra accounts or remove them.')" "CIS v8 5.4"
}

check_admins() {
  local members m unauthorized status detail
  if [ "$OS" = "Darwin" ]; then
    members=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership://' | tr ' ' '\n' | grep -v '^root$' | grep .)
  else
    members=$( { getent group sudo; getent group wheel; getent group admin; } 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep . | sort -u)
  fi
  unauthorized=""
  for m in $members; do
    case ",$ALLOWED_ADMINS," in *",$m,"*) ;; *) unauthorized="$unauthorized $m" ;; esac
  done
  unauthorized="${unauthorized# }"
  if [ -z "$members" ]; then status=PASS; detail="$(t 'No hay usuarios en los grupos de administración.' 'No users in admin groups.')"
  elif [ -z "$ALLOWED_ADMINS" ]; then status=WARN; detail="$(t "Administradores: $(echo $members). Define los autorizados con -a." "Admins: $(echo $members). Define allowed ones with -a.")"
  elif [ -z "$unauthorized" ]; then status=PASS; detail="$(t "Administradores autorizados: $(echo $members)." "Authorized admins: $(echo $members).")"
  else status=FAIL; detail="$(t "Administradores no autorizados: $unauthorized" "Unauthorized admins: $unauthorized")"; fi
  add_result "ACC-02" Accounts High "$status" "$(t 'Administradores autorizados' 'Authorized administrators')" "$detail" \
    "$(t 'Quita al usuario del grupo sudo/wheel/admin: sudo gpasswd -d USUARIO sudo' 'Remove the user from sudo/wheel/admin: sudo gpasswd -d USER sudo')" "CIS v8 5.4"
}

check_password_policy() {
  local status detail minlen
  if [ "$OS" = "Darwin" ]; then
    status=INFO; detail="$(t 'En macOS la política se gestiona con MDM o pwpolicy; revísala en la consola de gestión.' 'On macOS the policy is managed by MDM or pwpolicy; review it in the management console.')"
  else
    minlen=$(grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | tail -1 | sed 's/.*=\s*//' | tr -dc '0-9')
    [ -z "$minlen" ] && minlen=0
    detail="$(t "Longitud mínima (pwquality): $minlen; requerido: $MIN_PASS_LEN." "Minimum length (pwquality): $minlen; required: $MIN_PASS_LEN.")"
    if [ "$minlen" -ge "$MIN_PASS_LEN" ]; then status=PASS; else status=FAIL; fi
  fi
  add_result "ACC-03" Accounts High "$status" "$(t 'Política de contraseñas' 'Password policy')" "$detail" \
    "$(t "sudo apt install libpam-pwquality y define minlen = $MIN_PASS_LEN en /etc/security/pwquality.conf" "sudo apt install libpam-pwquality and set minlen = $MIN_PASS_LEN in /etc/security/pwquality.conf")" "CIS v8 5.2"
}

check_empty_passwords() {
  local status detail users
  if [ "$OS" = "Darwin" ]; then status=INFO; detail="$(t 'No aplica en macOS.' 'Not applicable on macOS.')"
  elif [ "$IS_ROOT" -eq 0 ]; then status=ERROR; detail="$(need_root_detail)"
  else
    users=$(awk -F: '($2==""){print $1}' /etc/shadow | tr '\n' ' '); users="${users% }"
    if [ -z "$users" ]; then status=PASS; detail="$(t 'Ninguna cuenta tiene contraseña vacía.' 'No account has an empty password.')"
    else status=FAIL; detail="$(t "Cuentas sin contraseña: $users" "Accounts without password: $users")"; fi
  fi
  add_result "ACC-04" Accounts High "$status" "$(t 'Sin cuentas con contraseña vacía' 'No accounts with empty password')" "$detail" \
    "$(t 'Asigna contraseña o bloquea la cuenta: sudo passwd -l USUARIO' 'Set a password or lock the account: sudo passwd -l USER')" "CIS v8 5.2"
}

sshd_value() {
  # Valor efectivo de una directiva de sshd (sshd -T requiere root)
  local key="$1" val=""
  if [ "$IS_ROOT" -eq 1 ] && have sshd; then val=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k{print tolower($2); exit}'); fi
  if [ -z "$val" ] && [ -f /etc/ssh/sshd_config ]; then
    val=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk -v k="$key" 'tolower($1)==k{print tolower($2); exit}')
  fi
  printf '%s' "$val"
}

check_ssh() {
  local status detail val
  if [ ! -f /etc/ssh/sshd_config ]; then
    add_result "NET-01" Network High PASS "$(t 'SSH sin acceso directo de root' 'SSH denies root login')" "$(t 'Servidor SSH no instalado.' 'SSH server not installed.')" "" "CIS v8 5.4"
    add_result "NET-02" Network Medium INFO "$(t 'SSH sin autenticación por contraseña' 'SSH without password authentication')" "$(t 'Servidor SSH no instalado.' 'SSH server not installed.')" "" "CIS v8 4.1"
    return
  fi
  val=$(sshd_value permitrootlogin); [ -z "$val" ] && val="prohibit-password"
  case "$val" in
    no) status=PASS ;; prohibit-password|without-password) status=WARN ;; *) status=FAIL ;;
  esac
  detail="PermitRootLogin $val"
  add_result "NET-01" Network High "$status" "$(t 'SSH sin acceso directo de root' 'SSH denies root login')" "$detail" \
    "$(t 'En /etc/ssh/sshd_config: PermitRootLogin no; luego sudo systemctl restart ssh' 'In /etc/ssh/sshd_config: PermitRootLogin no; then restart ssh')" "CIS v8 5.4"
  val=$(sshd_value passwordauthentication); [ -z "$val" ] && val="yes"
  if [ "$val" = "no" ]; then status=PASS; else status=WARN; fi
  add_result "NET-02" Network Medium "$status" "$(t 'SSH sin autenticación por contraseña' 'SSH without password authentication')" "PasswordAuthentication $val" \
    "$(t 'Usa llaves SSH y define PasswordAuthentication no.' 'Use SSH keys and set PasswordAuthentication no.')" "CIS v8 4.1"
}

check_listening() {
  local ports detail
  if [ "$OS" = "Darwin" ]; then
    ports=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{split($9,a,":"); print a[length(a)]"/"$1}' | sort -u | tr '\n' ' ')
  elif have ss; then
    ports=$(ss -tulnH 2>/dev/null | awk '{print $5"/"$1}' | grep -vE '^(127\.|\[::1\]|::1)' | sed 's/.*://' | sort -u | tr '\n' ' ')
  else ports=""; fi
  ports="${ports% }"
  if [ -n "$ports" ]; then detail="$(t "Puertos en escucha: $ports" "Listening ports: $ports")"; else detail="$(t 'No se detectaron puertos expuestos.' 'No exposed ports detected.')"; fi
  add_result "NET-03" Network Low INFO "$(t 'Servicios de red expuestos' 'Exposed network services')" "$detail" "" "CIS v8 4.8"
}

check_screen_lock() {
  local status detail enabled delay
  if [ "$OS" = "Darwin" ]; then
    status=INFO; detail="$(t 'Verifica en Ajustes > Pantalla de bloqueo (o perfil MDM) que pida contraseña tras el protector.' 'Check System Settings > Lock Screen (or MDM profile) requires a password.')"
  elif have gsettings && [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    enabled=$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null)
    delay=$(gsettings get org.gnome.desktop.session idle-delay 2>/dev/null | tr -dc '0-9')
    [ -z "$delay" ] && delay=0
    detail="lock-enabled=$enabled, idle-delay=${delay}s"
    if [ "$enabled" = "true" ] && [ "$delay" -gt 0 ] && [ "$delay" -le 900 ]; then status=PASS; else status=FAIL; fi
  else
    status=INFO; detail="$(t 'Sin sesión gráfica; no aplica (servidor).' 'No graphical session; not applicable (server).')"
  fi
  add_result "SYS-01" System Medium "$status" "$(t 'Bloqueo automático de pantalla' 'Automatic screen lock')" "$detail" \
    "$(t 'gsettings set org.gnome.desktop.session idle-delay 600 y lock-enabled true' 'gsettings set org.gnome.desktop.session idle-delay 600 and lock-enabled true')" "CIS v8 4.3"
}

check_blocked_software() {
  local inventory found item status detail
  if [ "$OS" = "Darwin" ]; then inventory=$(ls /Applications 2>/dev/null)
  elif have dpkg-query; then inventory=$(dpkg-query -W -f='${Package}\n' 2>/dev/null)
  elif have rpm; then inventory=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null)
  else inventory=""; fi
  SW_COUNT=$(printf '%s\n' "$inventory" | grep -c .)
  found=""
  local IFS=','
  for item in $BLOCKED_SW; do
    [ -z "$item" ] && continue
    if printf '%s\n' "$inventory" | grep -qi -- "$item"; then found="$found $item"; fi
  done
  unset IFS
  found="${found# }"
  if [ -z "$found" ]; then status=PASS; detail="$(t "Revisados $SW_COUNT paquetes contra la lista de bloqueo." "Reviewed $SW_COUNT packages against the blocklist.")"
  else status=FAIL; detail="$(t "Encontrado: $found" "Found: $found")"; fi
  add_result "SW-01" Software High "$status" "$(t 'Sin software no autorizado' 'No unauthorized software')" "$detail" \
    "$(t 'Desinstala el software o solicita su aprobación formal.' 'Uninstall it or request formal approval.')" "CIS v8 2.3"
}

check_password_files() {
  local base hits count status detail
  if [ "$OS" = "Darwin" ]; then base="/Users"; else base="/home"; fi
  hits=$(find "$base" -maxdepth 4 -type f \( -path '*/Desktop/*' -o -path '*/Escritorio/*' -o -path '*/Documents/*' -o -path '*/Documentos/*' -o -path '*/Downloads/*' -o -path '*/Descargas/*' \) 2>/dev/null \
    | grep -iE '(passw|contrase|clave|credencial|credential)[^/]*\.(txt|csv|xlsx|xls|docx|doc|odt|ods|rtf)$' | head -20)
  count=$(printf '%s' "$hits" | grep -c .)
  if [ "$count" -eq 0 ]; then status=PASS; detail="$(t 'No se encontraron archivos sospechosos.' 'No suspicious files found.')"
  else status=WARN; detail="$(t "Posibles archivos de contraseñas ($count): " "Possible password files ($count): ")$(printf '%s' "$hits" | head -5 | tr '\n' ';' | sed 's/;$//; s/;/; /g')"; fi
  add_result "BHV-01" Behavior Medium "$status" "$(t 'Sin archivos de contraseñas en texto plano' 'No plaintext password files')" "$detail" \
    "$(t 'Mueve las credenciales a un gestor de contraseñas y borra los archivos.' 'Move credentials to a password manager and delete the files.')" "CIS v8 14.3"
}

check_uptime() {
  local secs days status
  if [ "$OS" = "Darwin" ]; then
    secs=$(( $(date +%s) - $(sysctl -n kern.boottime | sed 's/.*sec = \([0-9]*\).*/\1/') ))
  else secs=$(cut -d. -f1 /proc/uptime); fi
  days=$(( secs / 86400 ))
  if [ "$days" -le "$MAX_UPTIME_DAYS" ]; then status=PASS; else status=WARN; fi
  add_result "BHV-02" Behavior Low "$status" "$(t 'El equipo se reinicia con regularidad' 'Device is rebooted regularly')" \
    "$(t "Encendido desde hace $days día(s); máximo: $MAX_UPTIME_DAYS." "Up for $days day(s); maximum: $MAX_UPTIME_DAYS.")" \
    "$(t 'Programa un reinicio semanal para aplicar parches.' 'Schedule a weekly reboot to apply patches.')" "CIS v8 7.3"
}

check_disk() {
  local used free status
  used=$(df -P / | awk 'NR==2{gsub("%","",$5); print $5}')
  free=$(( 100 - used ))
  if [ "$free" -ge "$MIN_FREE_PCT" ]; then status=PASS; else status=WARN; fi
  add_result "MNT-01" Maintenance Low "$status" "$(t 'Espacio libre en el disco raíz' 'Free space on root disk')" \
    "$(t "Libre: $free %; mínimo: $MIN_FREE_PCT %." "Free: $free %; minimum: $MIN_FREE_PCT %.")" \
    "$(t 'Limpia con: sudo apt autoremove && sudo journalctl --vacuum-time=14d' 'Clean with: sudo apt autoremove && sudo journalctl --vacuum-time=14d')" "$(t 'Mantenimiento preventivo' 'Preventive maintenance')"
}

check_domain() {
  local current status
  if [ "$OS" = "Darwin" ]; then current=$(dsconfigad -show 2>/dev/null | awk -F'= ' '/Active Directory Domain/{print $2}')
  elif have realm; then current=$(realm list --name-only 2>/dev/null | head -1)
  else current=""; fi
  if [ -z "$EXPECTED_DOMAIN" ]; then
    status=INFO
  elif [ "$(lower "$current")" = "$(lower "$EXPECTED_DOMAIN")" ]; then status=PASS
  else status=FAIL; fi
  [ -z "$current" ] && current="$(t 'ninguno' 'none')"
  add_result "DOM-01" Domain Medium "$status" "$(t 'Membresía de dominio' 'Domain membership')" "$(t "Dominio actual: $current" "Current domain: $current")${EXPECTED_DOMAIN:+ ($(t 'esperado' 'expected'): $EXPECTED_DOMAIN)}" \
    "$(t "sudo realm join $EXPECTED_DOMAIN -U administrador" "sudo realm join $EXPECTED_DOMAIN -U administrator")" "CIS v8 1.1"
}

# ---------------------------------------------------------------- inventario
collect_inventory() {
  INV_HOST=$(hostname 2>/dev/null || uname -n)
  INV_KERNEL=$(uname -r)
  if [ "$OS" = "Darwin" ]; then
    INV_OS="macOS $(sw_vers -productVersion 2>/dev/null)"
    INV_MODEL=$(sysctl -n hw.model 2>/dev/null)
    INV_SERIAL=$(ioreg -l 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')
    INV_CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
    INV_RAM=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 ))
    INV_IP=$(ipconfig getifaddr en0 2>/dev/null)
  else
    INV_OS=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")
    INV_MODEL="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null) $(cat /sys/class/dmi/id/product_name 2>/dev/null)"
    INV_SERIAL=$(cat /sys/class/dmi/id/product_serial 2>/dev/null)
    INV_CPU=$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo)
    INV_RAM=$(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo)
    INV_IP=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9.]+$' | grep -v '^127\.' | tr '\n' ' ')
  fi
  INV_MODEL=$(echo $INV_MODEL); INV_IP=$(echo $INV_IP)
  [ -z "$INV_SERIAL" ] && INV_SERIAL="$( [ "$IS_ROOT" -eq 1 ] && t 'no disponible' 'not available' || t 'requiere sudo' 'requires sudo')"
  INV_USER="${SUDO_USER:-$(id -un)}"
}

# ---------------------------------------------------------------- anonimizar
scrub() {
  local text="$1" u
  [ "$ANONYMIZE" -eq 1 ] || { printf '%s' "$text"; return; }
  text="${text//$REAL_HOST/$ANON_HOST}"
  [ -n "$REAL_SERIAL" ] && text="${text//$REAL_SERIAL/SERIE-OCULTA}"
  local i=1
  for u in $ANON_USERS; do text="${text//$u/usuario$i}"; i=$((i+1)); done
  printf '%s' "$text" | sed -E 's/([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}/\1.\2.x.x/g'
}

prepare_anonymization() {
  REAL_HOST="$INV_HOST"; REAL_SERIAL="$INV_SERIAL"
  local h
  if have sha256sum; then h=$(printf '%s' "$INV_HOST" | tr '[:lower:]' '[:upper:]' | sha256sum | cut -c1-6)
  else h=$(printf '%s' "$INV_HOST" | tr '[:lower:]' '[:upper:]' | shasum -a 256 | cut -c1-6); fi
  ANON_HOST="EQUIPO-$(printf '%s' "$h" | tr '[:lower:]' '[:upper:]')"
  if [ "$OS" = "Darwin" ]; then ANON_USERS=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=500{print $1}')
  else ANON_USERS=$(awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd); fi
  ANON_USERS="$ANON_USERS ${SUDO_USER:-} $(id -un)"
  ANON_USERS=$(printf '%s\n' $ANON_USERS | grep -E '^.{3,}$' | grep -vx root | sort -u | awk '{print length, $0}' | sort -rn | cut -d' ' -f2-)
}

# ---------------------------------------------------------------- salida
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e $'s/\t/\\\\t/g' | awk 'BEGIN{ORS=""} NR>1{print "\\n"} {print}'; }
html_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

compute_verdict() {
  local i n s
  N_PASS=0; N_FAIL=0; N_WARN=0; N_INFO=0; N_ERR=0; N_CRIT=0
  n=${#R_ID[@]}
  for ((i=0; i<n; i++)); do
    s="${R_STATUS[$i]}"
    case "$s" in PASS) N_PASS=$((N_PASS+1)) ;; FAIL) N_FAIL=$((N_FAIL+1)); [ "${R_SEV[$i]}" = "High" ] && N_CRIT=$((N_CRIT+1)) ;;
      WARN) N_WARN=$((N_WARN+1)) ;; INFO) N_INFO=$((N_INFO+1)) ;; *) N_ERR=$((N_ERR+1)) ;; esac
  done
  local scored=$(( n - N_INFO ))
  if [ "$scored" -gt 0 ]; then SCORE=$(( (N_PASS * 100 + scored / 2) / scored )); else SCORE=0; fi
  if [ "$N_CRIT" -gt 0 ]; then VERDICT_CODE="NOT_CERTIFIED"; VERDICT_LABEL="$(t 'NO CERTIFICADO' 'NOT CERTIFIED')"; EXIT_CODE=2
  elif [ $((N_FAIL + N_WARN + N_ERR)) -gt 0 ]; then VERDICT_CODE="CERTIFIED_WITH_OBSERVATIONS"; VERDICT_LABEL="$(t 'CERTIFICADO CON OBSERVACIONES' 'CERTIFIED WITH OBSERVATIONS')"; EXIT_CODE=1
  else VERDICT_CODE="CERTIFIED"; VERDICT_LABEL="$(t 'CERTIFICADO' 'CERTIFIED')"; EXIT_CODE=0; fi
}

write_json() {
  local f="$1" i n sep=""
  n=${#R_ID[@]}
  {
    printf '{\n  "Metadata": {"Tool": "certify-endpoint.sh", "Version": "%s", "Date": "%s", "Technician": "%s", "Profile": "'"$PROFILE"'", "Language": "%s", "RunAsRoot": %s, "Anonymized": %s},\n' \
      "$VERSION" "$RUN_DATE" "$(json_escape "$(scrub "$INV_USER")")" "$LANG_SEL" "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)" "$([ "$ANONYMIZE" -eq 1 ] && echo true || echo false)"
    printf '  "Verdict": {"Code": "%s", "Label": "%s", "Score": %s, "Pass": %s, "Fail": %s, "Warn": %s, "Error": %s, "Info": %s, "CriticalFail": %s},\n' \
      "$VERDICT_CODE" "$VERDICT_LABEL" "$SCORE" "$N_PASS" "$N_FAIL" "$N_WARN" "$N_ERR" "$N_INFO" "$N_CRIT"
    printf '  "Inventory": {"Hostname": "%s", "OS": "%s", "Kernel": "%s", "Model": "%s", "SerialNumber": "%s", "CPU": "%s", "RamGB": "%s", "IPv4": "%s"},\n' \
      "$(json_escape "$(scrub "$INV_HOST")")" "$(json_escape "$INV_OS")" "$(json_escape "$INV_KERNEL")" "$(json_escape "$INV_MODEL")" \
      "$(json_escape "$(scrub "$INV_SERIAL")")" "$(json_escape "$INV_CPU")" "$INV_RAM" "$(json_escape "$(scrub "$INV_IP")")"
    printf '  "Results": [\n'
    for ((i=0; i<n; i++)); do
      printf '%s    {"Id": "%s", "Category": "%s", "Severity": "%s", "Status": "%s", "Name": "%s", "Detail": "%s", "Remediation": "%s", "Reference": "%s"}' \
        "$sep" "${R_ID[$i]}" "${R_CAT[$i]}" "${R_SEV[$i]}" "${R_STATUS[$i]}" "$(json_escape "${R_NAME[$i]}")" \
        "$(json_escape "$(scrub "${R_DETAIL[$i]}")")" "$(json_escape "${R_FIX[$i]}")" "$(json_escape "${R_REF[$i]}")"
      sep=$',\n'
    done
    printf '\n  ]\n}\n'
  } > "$f"
}

write_csv() {
  local f="$1" i n
  csvq() { printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"; }
  n=${#R_ID[@]}
  {
    printf '\xEF\xBB\xBF'
    printf '%s\n' "$(t 'ID,Categoría,Control,Severidad,Estado,Detalle,Corrección,Referencia' 'ID,Category,Control,Severity,Status,Detail,Fix,Reference')"
    for ((i=0; i<n; i++)); do
      printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "${R_ID[$i]}" "$(csvq "$(cat_label "${R_CAT[$i]}")")" "$(csvq "${R_NAME[$i]}")" "$(sev_label "${R_SEV[$i]}")" \
        "$(csvq "$(status_label "${R_STATUS[$i]}")")" "$(csvq "$(scrub "${R_DETAIL[$i]}")")" "$(csvq "${R_FIX[$i]}")" "$(csvq "${R_REF[$i]}")"
    done
  } > "$f"
}

write_html() {
  local f="$1" i n badge cls s order
  case "$VERDICT_CODE" in CERTIFIED) badge=ok ;; CERTIFIED_WITH_OBSERVATIONS) badge=warn ;; *) badge=bad ;; esac
  n=${#R_ID[@]}
  {
    cat <<EOF
<!doctype html>
<html lang="$LANG_SEL"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(t 'Certificación de equipo' 'Endpoint certification') - $(html_escape "$(scrub "$INV_HOST")")</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d232b;--muted:#5d6876;--line:#dfe3e8;--ok:#127a3e;--okbg:#e3f4e9;--warn:#8a5a00;--warnbg:#fdf1d6;--bad:#b42318;--badbg:#fde5e2;--info:#1f5fa8;--infobg:#e3eefb;--err:#7a2e8a;--errbg:#f3e4f6}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--ink:#e6e9ee;--muted:#9aa4b1;--line:#2e343d;--okbg:#14321f;--ok:#6fd49a;--warnbg:#3a2e10;--warn:#f2c35b;--badbg:#3d1714;--bad:#ff8a80;--infobg:#132a45;--info:#8bbcf2;--errbg:#33193a;--err:#d9a3e6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}.hero{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center}
.badge{display:inline-block;padding:8px 14px;border-radius:8px;font-weight:700}.ok{background:var(--okbg);color:var(--ok)}.warn{background:var(--warnbg);color:var(--warn)}.bad{background:var(--badbg);color:var(--bad)}.info{background:var(--infobg);color:var(--info)}.err{background:var(--errbg);color:var(--err)}
.score{font-size:40px;font-weight:700;text-align:right}.stats{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.pill{padding:3px 10px;border-radius:999px;font-size:13px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:13px;color:var(--muted)}
td:first-child{white-space:nowrap}.kv td:first-child{width:220px;color:var(--muted)}.tag{white-space:nowrap;font-size:12px;font-weight:700;padding:2px 8px;border-radius:6px}.fix{color:var(--muted);font-size:13px;margin-top:4px}.wrap{overflow-x:auto}footer{margin-top:32px;font-size:13px;color:var(--muted)}
@media (max-width:640px){.hero{grid-template-columns:1fr}.score{text-align:left}.kv td:first-child{width:auto}}
</style></head><body><main>
<h1>$(t 'Reporte de certificación de equipo' 'Endpoint certification report')</h1>
<p class="muted">$(t 'Fecha:' 'Date:') $RUN_DATE · $(t 'Técnico:' 'Technician:') $(html_escape "$(scrub "$INV_USER")") · $(t 'Perfil:' 'Profile:') $PROFILE</p>
<div class="card hero"><div><span class="badge $badge">$VERDICT_LABEL</span>
<div class="stats"><span class="pill ok">$(status_label PASS): $N_PASS</span><span class="pill bad">$(status_label FAIL): $N_FAIL</span><span class="pill warn">$(status_label WARN): $N_WARN</span><span class="pill err">ERROR: $N_ERR</span><span class="pill info">INFO: $N_INFO</span></div>
EOF
    [ "$N_CRIT" -gt 0 ] && printf '<p class="muted">%s</p>\n' "$(t "Hay $N_CRIT control(es) de severidad alta sin cumplir; el equipo no se puede entregar hasta corregirlos." "$N_CRIT high-severity control(s) failed; the device cannot be released until fixed.")"
    [ "$IS_ROOT" -eq 0 ] && printf '<p class="muted">%s</p>\n' "$(t 'Ejecutado sin sudo: algunos controles no se pudieron evaluar.' 'Run without sudo: some controls could not be evaluated.')"
    printf '</div><div class="score">%s%%<div class="muted" style="font-size:13px;font-weight:400">%s</div></div></div>\n' "$SCORE" "$(t 'controles cumplidos' 'controls passed')"
    printf '<h2>%s</h2><table class="kv"><tbody>\n' "$(t 'Ficha del equipo' 'Device record')"
    printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(t 'Equipo' 'Hostname')" "$(html_escape "$(scrub "$INV_HOST")")" \
      "$(t 'Sistema operativo' 'Operating system')" "$(html_escape "$INV_OS")" "Kernel" "$(html_escape "$INV_KERNEL")" \
      "$(t 'Modelo' 'Model')" "$(html_escape "$INV_MODEL")" "$(t 'Número de serie' 'Serial number')" "$(html_escape "$(scrub "$INV_SERIAL")")" \
      "CPU" "$(html_escape "$INV_CPU")" "RAM (GB)" "$INV_RAM" "IPv4" "$(html_escape "$(scrub "$INV_IP")")"
    printf '</tbody></table>\n<h2>%s</h2><div class="wrap"><table><thead><tr><th>ID</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>\n' \
      "$(t 'Resultados por control' 'Results by control')" "$(t 'Categoría' 'Category')" "$(t 'Control y hallazgo' 'Control and finding')" \
      "$(t 'Severidad' 'Severity')" "$(t 'Estado' 'Status')" "$(t 'Referencia' 'Reference')"
    for order in FAIL ERROR WARN PASS INFO; do
      for ((i=0; i<n; i++)); do
        s="${R_STATUS[$i]}"; [ "$s" = "$order" ] || continue
        case "$s" in PASS) cls=ok ;; FAIL) cls=bad ;; WARN) cls=warn ;; ERROR) cls=err ;; *) cls=info ;; esac
        printf '<tr><td>%s</td><td>%s</td><td><strong>%s</strong><div>%s</div>' "${R_ID[$i]}" "$(cat_label "${R_CAT[$i]}")" \
          "$(html_escape "${R_NAME[$i]}")" "$(html_escape "$(scrub "${R_DETAIL[$i]}")")"
        [ -n "${R_FIX[$i]}" ] && printf '<div class="fix">%s %s</div>' "$(t 'Corrección:' 'Fix:')" "$(html_escape "${R_FIX[$i]}")"
        printf '</td><td>%s</td><td><span class="tag %s">%s</span></td><td>%s</td></tr>\n' "$(sev_label "${R_SEV[$i]}")" "$cls" "$(status_label "$s")" "$(html_escape "${R_REF[$i]}")"
      done
    done
    printf '</tbody></table></div>\n<footer>certify-endpoint.sh v%s · %s</footer>\n</main></body></html>\n' "$VERSION" \
      "$(t 'Criterio: un control de severidad alta sin cumplir impide la certificación; cualquier otro hallazgo la deja con observaciones.' 'Rule: any failed high-severity control blocks certification; other findings result in observations.')"
  } > "$f"
}

# ---------------------------------------------------------------- principal
echo ""
echo "${C_C}$(t '=== Certificación de equipo ===' '=== Endpoint certification ===')${C_0}"
[ "$IS_ROOT" -eq 0 ] && echo "${C_Y}$(t 'Aviso: ejecuta con sudo para evaluar todos los controles.' 'Note: run with sudo to evaluate every control.')${C_0}"
echo ""

check_firewall
check_encryption
check_antimalware
check_updates
check_auto_updates
check_reboot
check_uid0
check_admins
check_password_policy
check_empty_passwords
check_ssh
check_listening
check_screen_lock
check_blocked_software
check_password_files
check_uptime
check_disk
check_domain

collect_inventory
[ "$ANONYMIZE" -eq 1 ] && prepare_anonymization
compute_verdict

RUN_DATE=$(date '+%Y-%m-%d %H:%M')
mkdir -p "$OUT_DIR" || { echo "$(t 'No se pudo crear la carpeta de salida.' 'Could not create output folder.')" >&2; exit 3; }
SAFE_HOST=$(scrub "$INV_HOST" | tr -c 'A-Za-z0-9_-' '_')
BASE="$OUT_DIR/cert_${SAFE_HOST}_$(date '+%Y%m%d-%H%M%S')"
write_json "$BASE.json"
write_csv "$BASE.csv"
write_html "$BASE.html"
# Si se ejecutó con sudo, devuelve los reportes al usuario que lo invocó
if [ -n "${SUDO_USER:-}" ]; then chown "$SUDO_USER" "$BASE".* "$OUT_DIR" 2>/dev/null; fi

echo ""
case "$EXIT_CODE" in 0) col="$C_G" ;; 1) col="$C_Y" ;; *) col="$C_R" ;; esac
echo "${col}$(t 'Veredicto:' 'Verdict:') $VERDICT_LABEL ($SCORE%)${C_0}"
echo "$(t 'Reporte HTML:' 'HTML report:') $BASE.html"
echo "$(t 'Datos JSON:  ' 'JSON data:   ') $BASE.json"
echo "$(t 'Tabla CSV:   ' 'CSV table:   ') $BASE.csv"
exit "$EXIT_CODE"
