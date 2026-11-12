# Endpoint Certification · Certificación de equipos

[Español](#español) · [English](#english)

---

## Español

Scripts que certifican y recertifican equipos de cómputo contra una línea base de seguridad, como lo hace un área de soporte N1/N2 antes de entregar un equipo a un usuario. Revisan antivirus, firewall, cifrado, parches, cuentas, red, software no autorizado y malas prácticas del usuario, y emiten un veredicto con un reporte HTML, JSON y CSV.

| Script | Sistema | Controles |
| --- | --- | --- |
| `Invoke-EndpointCertification.ps1` | Windows 10/11 (PowerShell 5.1 o 7) | 27 |
| `certify-endpoint.sh` | Linux (Ubuntu/Debian, RHEL/Fedora) y macOS | 19 |

### Por qué existe

En soporte técnico, cada equipo que se entrega o se revisa necesita una revisión repetible: misma lista, mismo criterio, evidencia guardada. Hacerlo a mano toma 20-30 minutos por equipo y depende de quién lo haga. Este script lo hace en menos de un minuto y deja un reporte que se puede adjuntar al ticket.

### Veredicto

| Resultado | Regla |
| --- | --- |
| **CERTIFICADO** | Todos los controles cumplen. |
| **CERTIFICADO CON OBSERVACIONES** | Hay advertencias o fallos de severidad media o baja. |
| **NO CERTIFICADO** | Al menos un control de severidad **alta** no cumple. El equipo no se entrega hasta corregirlo. |

Códigos de salida: `0` certificado, `1` con observaciones, `2` no certificado, `3` error. Sirven para automatizar la revisión desde una tarea programada, Intune o un pipeline.

### Controles de Windows

| ID | Control | Severidad | Referencia |
| --- | --- | --- | --- |
| SEC-01 | Antivirus activo con protección en tiempo real | Alta | CIS v8 10.1 |
| SEC-02 | Firmas del antivirus actualizadas | Media | CIS v8 10.2 |
| SEC-03 | Firewall activo en todos los perfiles | Alta | CIS v8 4.5 |
| SEC-04 | Disco del sistema cifrado (BitLocker) | Alta | CIS v8 3.6 |
| SEC-05 | Secure Boot habilitado | Media | CIS v8 4.1 |
| SEC-06 | TPM presente y listo | Baja | CIS v8 4.1 |
| PAT-01 | Actualizaciones de Windows recientes | Alta | CIS v8 7.3 |
| PAT-02 | Sin reinicio pendiente | Media | CIS v8 7.3 |
| ACC-01 | Solo administradores locales autorizados | Alta | CIS v8 5.4 |
| ACC-02 | Cuenta Administrador integrada deshabilitada | Media | CIS v8 4.7 |
| ACC-03 | Cuenta Invitado deshabilitada | Media | CIS v8 4.7 |
| ACC-04 | Política de contraseñas (longitud y complejidad) | Alta | CIS v8 5.2 |
| ACC-05 | Bloqueo de cuenta tras intentos fallidos | Media | CIS v8 4.10 |
| ACC-06 | Bloqueo automático de pantalla | Media | CIS v8 4.3 |
| ACC-07 | Sin inicio de sesión automático ni contraseña en el registro | Alta | CIS v8 5.2 |
| NET-01 | SMBv1 deshabilitado | Alta | CIS v8 4.8 |
| NET-02 | Escritorio remoto deshabilitado o con NLA | Media | CIS v8 4.1 |
| NET-03 | Sin carpetas compartidas abiertas a Todos | Media | CIS v8 3.3 |
| SYS-01 | UAC activo | Alta | CIS v8 4.1 |
| SYS-02 | AutoRun deshabilitado | Baja | CIS v8 10.3 |
| SYS-03 | Almacenamiento USB según la política | Media | Política interna |
| SW-01 | Sin software no autorizado | Alta | CIS v8 2.3 |
| SW-02 | Software corporativo requerido instalado | Media | CIS v8 2.1 |
| BHV-01 | Sin archivos de contraseñas en texto plano | Media | CIS v8 14.3 |
| BHV-02 | El equipo se reinicia con regularidad | Baja | CIS v8 7.3 |
| MNT-01 | Espacio libre suficiente en disco | Baja | Mantenimiento preventivo |
| DOM-01 | Membresía de dominio | Media | CIS v8 1.1 |

Además arma la ficha del equipo: fabricante, modelo, número de serie, CPU, RAM, versión de Windows, IP y lista de software instalado.

### Uso en Windows

Abre PowerShell **como administrador** en la carpeta del proyecto:

```powershell
# Permite ejecutar el script solo en esta ventana
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Certificación
.\Invoke-EndpointCertification.ps1

# Equipo que debe estar en el dominio
.\Invoke-EndpointCertification.ps1 -ExpectedDomain lab.local

# Recertificación: compara contra el reporte anterior del mismo equipo
.\Invoke-EndpointCertification.ps1 -PreviousReport .\reports\cert_PC01_20261105-101500.json

# Reporte en inglés y anonimizado para publicarlo
.\Invoke-EndpointCertification.ps1 -Language en -Anonymize
```

El reporte se guarda en `.\reports\` y se abre solo en el navegador.

### Uso en Linux y macOS

```bash
chmod +x certify-endpoint.sh
sudo ./certify-endpoint.sh -a soporte              # administradores autorizados
sudo ./certify-endpoint.sh -p server -d lab.local  # perfil de servidor y dominio esperado
sudo ./certify-endpoint.sh -l en -A                # inglés y anonimizado
```

### Línea base

`baseline.json` define los umbrales sin tocar el código: días máximos sin parches, longitud mínima de contraseña, administradores autorizados, software bloqueado y software requerido. Cada empresa ajusta su propio archivo.

```json
{
  "MinPasswordLength": 12,
  "AllowedLocalAdmins": ["soporte"],
  "BlockedSoftware": ["AnyDesk", "TeamViewer", "uTorrent"],
  "RequiredSoftware": ["GLPI Agent", "Wazuh Agent"]
}
```

### Resultados en el laboratorio

<!-- Reemplaza las capturas con las tuyas (docs/img) y completa la tabla con tus números reales. -->

| Equipo | Primera certificación | Después de remediar |
| --- | --- | --- |
| Windows 11 Enterprise (VM) | NO CERTIFICADO · __ % | CERTIFICADO · __ % |
| Ubuntu Server 24.04 (VM) | NO CERTIFICADO · __ % | CERTIFICADO CON OBSERVACIONES · __ % |

![Reporte antes de remediar](docs/img/01-antes.png)
![Recertificación después de remediar](docs/img/02-recertificacion.png)

### Decisiones técnicas

- **No depende del idioma.** Los grupos se buscan por SID (`S-1-5-32-544` es Administradores en cualquier idioma) y la política de contraseñas se lee con `secedit`, cuyas claves no se traducen. Funciona igual en Windows en español o en inglés.
- **Solo lectura.** El script no cambia nada en el equipo; cada hallazgo trae el comando o la ruta para corregirlo.
- **Sin dependencias.** Usa lo que ya trae Windows (PowerShell 5.1) o el sistema (bash 3.2+).
- **Privacidad.** `-Anonymize` reemplaza nombre del equipo, número de serie, usuarios e IPs por marcadores estables, para publicar reportes sin exponer datos.
- **Recertificación.** Con `-PreviousReport` el reporte muestra qué controles mejoraron o empeoraron desde la revisión anterior.

### Limitaciones conocidas

- La política de contraseñas que se lee es la local. En equipos de dominio, la política efectiva para cuentas de dominio la define el controlador de dominio.
- El bloqueo de pantalla del usuario se lee del perfil que ejecuta el script.
- La parte de macOS no se ha probado en un equipo físico.
- El script de Linux/macOS todavía no compara contra un reporte anterior.

### Estructura

```
endpoint-certification/
├── Invoke-EndpointCertification.ps1   # Windows
├── certify-endpoint.sh                # Linux y macOS
├── baseline.json                      # Línea base editable
├── reports/                           # Reportes generados (ignorados por Git)
└── docs/img/                          # Capturas para este README
```

---

## English

Scripts that certify and recertify endpoints against a security baseline, the way an IT support team checks a device before handing it to a user. They review antivirus, firewall, disk encryption, patching, accounts, network exposure, unauthorized software and risky user habits, then issue a verdict with an HTML, JSON and CSV report.

| Script | OS | Controls |
| --- | --- | --- |
| `Invoke-EndpointCertification.ps1` | Windows 10/11 (PowerShell 5.1 or 7) | 27 |
| `certify-endpoint.sh` | Linux (Ubuntu/Debian, RHEL/Fedora) and macOS | 19 |

### Why

Every device that IT hands out or reviews needs a repeatable check: same list, same criteria, saved evidence. Done by hand it takes 20-30 minutes per device and depends on who does it. This script does it in under a minute and produces a report you can attach to the ticket.

### Verdict

| Result | Rule |
| --- | --- |
| **CERTIFIED** | Every control passes. |
| **CERTIFIED WITH OBSERVATIONS** | Warnings or medium/low-severity failures. |
| **NOT CERTIFIED** | At least one **high**-severity control fails. The device is not released until it is fixed. |

Exit codes: `0` certified, `1` with observations, `2` not certified, `3` error, so the check can run from a scheduled task, Intune or a pipeline.

The Windows control list is in the Spanish section above (IDs, severity and CIS Controls v8 mapping are the same in both languages). The report itself switches language with `-Language en`.

### Usage on Windows

Open PowerShell **as administrator** in the project folder:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Invoke-EndpointCertification.ps1 -Language en
.\Invoke-EndpointCertification.ps1 -Language en -ExpectedDomain lab.local
.\Invoke-EndpointCertification.ps1 -Language en -PreviousReport .\reports\cert_PC01_20261105-101500.json
.\Invoke-EndpointCertification.ps1 -Language en -Anonymize
```

### Usage on Linux and macOS

```bash
chmod +x certify-endpoint.sh
sudo ./certify-endpoint.sh -l en -a support
sudo ./certify-endpoint.sh -l en -p server -d lab.local
```

### Baseline

`baseline.json` holds the thresholds (patch age, password length, allowed admins, blocked and required software) so each organization tunes its own policy without editing code.

### Design decisions

- **Language independent.** Groups are resolved by SID and password policy is read through `secedit`, whose keys are never translated, so it behaves the same on Spanish or English Windows.
- **Read only.** Nothing on the device is changed; every finding includes the command or setting that fixes it.
- **No dependencies.** Built-in PowerShell 5.1 on Windows; bash 3.2+ on Linux and macOS.
- **Privacy.** `-Anonymize` replaces hostname, serial number, user names and IPs with stable placeholders before a report is shared.
- **Recertification.** `-PreviousReport` shows which controls improved or degraded since the last review.

### Known limitations

- Password policy is read from local policy; on domain-joined devices the domain controller defines the effective policy for domain accounts.
- Screen lock settings are read from the profile running the script.
- macOS support has not been tested on physical hardware.
- The Linux/macOS script does not compare against a previous report yet.

---

Autor / Author: Aldo · Systems Engineering, UNITEC
