<#
.SYNOPSIS
    Certificación y recertificación de endpoints Windows contra una línea base de seguridad.
    Windows endpoint certification and recertification against a security baseline.

.DESCRIPTION
    Evalúa 27 controles (antivirus, firewall, cifrado, parches, cuentas, red, software y
    hábitos de usuario), emite un veredicto (CERTIFICADO / CERTIFICADO CON OBSERVACIONES /
    NO CERTIFICADO) y genera reportes HTML, JSON y CSV. Con -PreviousReport compara contra
    una certificación anterior para documentar la recertificación.

    Evaluates 27 controls, issues a verdict and writes HTML, JSON and CSV reports.
    With -PreviousReport it compares against an earlier run (recertification).

    Compatible con Windows PowerShell 5.1 y PowerShell 7. No depende del idioma del sistema.

.PARAMETER Language
    Idioma del reporte: es (predeterminado) o en.

.PARAMETER BaselinePath
    Ruta del archivo JSON con la línea base. Si no existe, se usan valores predeterminados.

.PARAMETER OutputPath
    Carpeta donde se guardan los reportes. Predeterminado: .\reports

.PARAMETER PreviousReport
    Reporte JSON de una certificación anterior del mismo equipo (recertificación).

.PARAMETER ExpectedDomain
    Dominio al que el equipo debe estar unido (por ejemplo lab.local).

.PARAMETER Technician
    Nombre del técnico que certifica. Predeterminado: usuario actual.

.PARAMETER Anonymize
    Oculta nombre del equipo, número de serie, usuarios e IPs. Úsalo antes de publicar un reporte.

.PARAMETER NoOpen
    No abre el reporte HTML al terminar.

.EXAMPLE
    .\Invoke-EndpointCertification.ps1

.EXAMPLE
    .\Invoke-EndpointCertification.ps1 -ExpectedDomain lab.local -PreviousReport .\reports\cert_PC01_20261105-101500.json

.EXAMPLE
    .\Invoke-EndpointCertification.ps1 -Language en -Anonymize

.NOTES
    Códigos de salida: 0 = certificado, 1 = certificado con observaciones, 2 = no certificado, 3 = error.
    Exit codes: 0 = certified, 1 = certified with observations, 2 = not certified, 3 = error.
#>
[CmdletBinding()]
param(
    [ValidateSet('es', 'en')]
    [string]$Language = 'es',

    [string]$BaselinePath = (Join-Path $PSScriptRoot 'baseline.json'),

    [string]$OutputPath = (Join-Path $PSScriptRoot 'reports'),

    [string]$PreviousReport,

    [string]$ExpectedDomain,

    [string]$Technician = $env:USERNAME,

    [switch]$Anonymize,

    [switch]$NoOpen
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Version = '1.0.0'
$script:Lang = $Language
$script:Cache = @{}

#region ---------- Utilidades / Helpers ----------

function L {
    # Devuelve el texto en el idioma elegido / Returns the text in the selected language
    param([string]$Es, [string]$En)
    if ($script:Lang -eq 'en') { return $En } else { return $Es }
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

function Get-DefaultBaseline {
    return [pscustomobject]@{
        MaxSignatureAgeDays    = 7
        MaxDaysSinceLastUpdate = 45
        MinPasswordLength      = 12
        MaxLockoutThreshold    = 10
        MaxScreenLockSeconds   = 900
        MinFreeSpacePercent    = 15
        MaxUptimeDays          = 14
        BlockUsbStorage        = $false
        AllowedLocalAdmins     = @()
        BlockedSoftware        = @('uTorrent', 'BitTorrent', 'qBittorrent', 'Vuze', 'AnyDesk', 'TeamViewer', 'UltraViewer', 'Ammyy')
        RequiredSoftware       = @()
    }
}

function Get-Baseline {
    param([string]$Path)
    $baseline = Get-DefaultBaseline
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $custom = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($prop in $custom.PSObject.Properties) {
            if ($baseline.PSObject.Properties.Name -contains $prop.Name) {
                $baseline.($prop.Name) = $prop.Value
            }
        }
        $script:BaselineSource = (Resolve-Path -LiteralPath $Path).Path
    }
    else {
        $script:BaselineSource = (L 'Valores predeterminados del script' 'Script defaults')
    }
    # Normaliza listas / Normalize lists
    foreach ($listName in 'AllowedLocalAdmins', 'BlockedSoftware', 'RequiredSoftware') {
        $baseline.$listName = @($baseline.$listName | Where-Object { $_ })
    }
    return $baseline
}

function Get-InstalledSoftware {
    if ($script:Cache.ContainsKey('Software')) { return $script:Cache['Software'] }
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName } |
            ForEach-Object {
                $ver = $null; $pub = $null
                if ($_.PSObject.Properties.Name -contains 'DisplayVersion') { $ver = $_.DisplayVersion }
                if ($_.PSObject.Properties.Name -contains 'Publisher') { $pub = $_.Publisher }
                [pscustomobject]@{ Name = [string]$_.DisplayName; Version = [string]$ver; Publisher = [string]$pub }
            }
    }
    $list = @($items | Sort-Object Name, Version -Unique)
    $script:Cache['Software'] = $list
    return $list
}

function Get-SecurityPolicy {
    # Exporta la política local con secedit (las claves no dependen del idioma)
    # Exports local policy with secedit (keys are language independent)
    if ($script:Cache.ContainsKey('SecPol')) { return $script:Cache['SecPol'] }
    $tmp = Join-Path $env:TEMP ('secpol_{0}.cfg' -f [guid]::NewGuid())
    try {
        $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY 2>&1
        if (-not (Test-Path -LiteralPath $tmp)) {
            throw (L 'secedit no pudo exportar la política (se requiere administrador).' 'secedit could not export the policy (administrator required).')
        }
        $policy = @{}
        foreach ($line in Get-Content -LiteralPath $tmp) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$') { $policy[$Matches[1]] = $Matches[2] }
        }
        $script:Cache['SecPol'] = $policy
        return $policy
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-LocalAdminMembers {
    # Miembros del grupo Administradores por SID (S-1-5-32-544), sin depender del idioma
    $members = @()
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; SID = [string]$_.SID; Class = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource }
            })
    }
    catch {
        # Respaldo con ADSI (Get-LocalGroupMember falla con SIDs huérfanos)
        $groupName = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]("WinNT://$env:COMPUTERNAME/$groupName,group")
        $members = @($group.Invoke('Members') | ForEach-Object {
                $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
                $sidBytes = $_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
                $sid = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                $cls = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
                [pscustomobject]@{ Name = ($path -replace '^WinNT://', '' -replace '/', '\'); SID = $sid; Class = [string]$cls; Source = 'ADSI' }
            })
    }
    return $members
}

function ConvertTo-HtmlText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

#endregion

#region ---------- Motor de controles / Check engine ----------

$script:Labels = @{
    Status   = @{
        PASS  = @{ es = 'CUMPLE'; en = 'PASS' }
        FAIL  = @{ es = 'NO CUMPLE'; en = 'FAIL' }
        WARN  = @{ es = 'ADVERTENCIA'; en = 'WARNING' }
        INFO  = @{ es = 'INFO'; en = 'INFO' }
        ERROR = @{ es = 'ERROR'; en = 'ERROR' }
    }
    Severity = @{
        High   = @{ es = 'Alta'; en = 'High' }
        Medium = @{ es = 'Media'; en = 'Medium' }
        Low    = @{ es = 'Baja'; en = 'Low' }
    }
    Category = @{
        Security    = @{ es = 'Seguridad'; en = 'Security' }
        Patching    = @{ es = 'Parches'; en = 'Patching' }
        Accounts    = @{ es = 'Cuentas'; en = 'Accounts' }
        Network     = @{ es = 'Red'; en = 'Network' }
        System      = @{ es = 'Sistema'; en = 'System' }
        Software    = @{ es = 'Software'; en = 'Software' }
        Behavior    = @{ es = 'Hábitos de usuario'; en = 'User behavior' }
        Maintenance = @{ es = 'Mantenimiento'; en = 'Maintenance' }
        Domain      = @{ es = 'Dominio'; en = 'Domain' }
    }
    Verdict  = @{
        CERTIFIED                   = @{ es = 'CERTIFICADO'; en = 'CERTIFIED' }
        CERTIFIED_WITH_OBSERVATIONS = @{ es = 'CERTIFICADO CON OBSERVACIONES'; en = 'CERTIFIED WITH OBSERVATIONS' }
        NOT_CERTIFIED               = @{ es = 'NO CERTIFICADO'; en = 'NOT CERTIFIED' }
    }
}

function Get-Label {
    param([string]$Group, [string]$Key)
    $entry = $script:Labels[$Group][$Key]
    if ($null -eq $entry) { return $Key }
    return $entry[$script:Lang]
}

function Invoke-Check {
    param(
        [string]$Id,
        [string]$Category,
        [string]$Severity,
        [string]$Name,
        [string]$Remediation,
        [string]$Reference,
        [scriptblock]$Test
    )
    $status = 'ERROR'; $detail = ''
    try {
        $outcome = & $Test
        $status = $outcome.Status
        $detail = $outcome.Detail
    }
    catch {
        $status = 'ERROR'
        $msg = $_.Exception.Message
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $msg -match 'denied|denegado|privileg|elevat|administr') {
            $detail = (L 'Se requiere ejecutar como administrador para evaluar este control.' 'Run as administrator to evaluate this control.')
        }
        else {
            $detail = (L 'No se pudo evaluar: ' 'Could not evaluate: ') + $msg
        }
    }
    $result = [pscustomobject]@{
        Id            = $Id
        Category      = $Category
        CategoryLabel = (Get-Label 'Category' $Category)
        Name          = $Name
        Severity      = $Severity
        SeverityLabel = (Get-Label 'Severity' $Severity)
        Status        = $status
        StatusLabel   = (Get-Label 'Status' $status)
        Detail        = $detail
        Remediation   = $(if ($status -in 'PASS', 'INFO') { '' } else { $Remediation })
        Reference     = $Reference
    }
    Write-CheckLine $result
    return $result
}

function New-Outcome {
    param([ValidateSet('PASS', 'FAIL', 'WARN', 'INFO')][string]$Status, [string]$Detail)
    return @{ Status = $Status; Detail = $Detail }
}

function Write-CheckLine {
    param($Result)
    $color = switch ($Result.Status) {
        'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } 'ERROR' { 'Magenta' } default { 'Cyan' }
    }
    $tag = ('[{0}]' -f $Result.StatusLabel).PadRight(15)
    Write-Host ('  {0} ' -f $tag) -ForegroundColor $color -NoNewline
    Write-Host ('{0,-7} {1}' -f $Result.Id, $Result.Name)
}

#endregion

#region ---------- Controles / Checks ----------

function Invoke-AllChecks {
    param($Baseline)
    $b = $Baseline
    $results = New-Object System.Collections.Generic.List[object]

    # ---------------- Seguridad ----------------
    $results.Add((Invoke-Check -Id 'SEC-01' -Category 'Security' -Severity 'High' -Reference 'CIS v8 10.1' `
                -Name (L 'Antivirus activo con protección en tiempo real' 'Antivirus enabled with real-time protection') `
                -Remediation (L 'Activa Microsoft Defender (Seguridad de Windows > Protección antivirus) o el antivirus corporativo.' 'Enable Microsoft Defender or the corporate antivirus.') `
                -Test {
                $mp = $null
                try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mp = $null }
                if ($mp -and $mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {
                    $script:Cache['AvIsDefender'] = $true
                    return (New-Outcome PASS (L 'Microsoft Defender activo con protección en tiempo real.' 'Microsoft Defender active with real-time protection.'))
                }
                $script:Cache['AvIsDefender'] = $false
                $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
                $enabled = @($products | Where-Object { ('{0:x6}' -f [int]$_.productState).Substring(2, 2) -in '10', '11' })
                if ($enabled.Count -gt 0) {
                    return (New-Outcome PASS ((L 'Antivirus activo: ' 'Active antivirus: ') + (($enabled | ForEach-Object { $_.displayName }) -join ', ')))
                }
                return (New-Outcome FAIL (L 'No se encontró un antivirus activo con protección en tiempo real.' 'No active antivirus with real-time protection was found.'))
            }))

    $results.Add((Invoke-Check -Id 'SEC-02' -Category 'Security' -Severity 'Medium' -Reference 'CIS v8 10.2' `
                -Name (L 'Firmas del antivirus actualizadas' 'Antivirus signatures up to date') `
                -Remediation (L 'Actualiza las firmas: Update-MpSignature o desde la consola del antivirus.' 'Update signatures: Update-MpSignature or the antivirus console.') `
                -Test {
                if (-not $script:Cache['AvIsDefender']) {
                    return (New-Outcome INFO (L 'El antivirus activo no es Defender; verifica las firmas en su consola.' 'Active antivirus is not Defender; verify signatures in its console.'))
                }
                $age = [int](Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureAge
                $d = (L "Antigüedad de firmas: $age día(s); máximo permitido: $($b.MaxSignatureAgeDays)." "Signature age: $age day(s); maximum allowed: $($b.MaxSignatureAgeDays).")
                if ($age -le [int]$b.MaxSignatureAgeDays) { return (New-Outcome PASS $d) }
                return (New-Outcome FAIL $d)
            }))

    $results.Add((Invoke-Check -Id 'SEC-03' -Category 'Security' -Severity 'High' -Reference 'CIS v8 4.5' `
                -Name (L 'Firewall activo en todos los perfiles' 'Firewall enabled on all profiles') `
                -Remediation (L 'Ejecuta: Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True' 'Run: Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True') `
                -Test {
                $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
                $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
                if ($off.Count -eq 0) { return (New-Outcome PASS (L 'Dominio, Privado y Público activos.' 'Domain, Private and Public enabled.')) }
                return (New-Outcome FAIL ((L 'Perfiles desactivados: ' 'Disabled profiles: ') + ($off -join ', ')))
            }))

    $results.Add((Invoke-Check -Id 'SEC-04' -Category 'Security' -Severity 'High' -Reference 'CIS v8 3.6' `
                -Name (L 'Disco del sistema cifrado (BitLocker)' 'System drive encrypted (BitLocker)') `
                -Remediation (L 'Activa BitLocker en la unidad del sistema y guarda la clave de recuperación en el directorio de la empresa.' 'Enable BitLocker on the system drive and escrow the recovery key.') `
                -Test {
                $vol = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume `
                    -Filter ("DriveLetter='{0}'" -f $env:SystemDrive) -ErrorAction Stop
                if ($null -eq $vol) { return (New-Outcome FAIL (L 'La unidad del sistema no admite cifrado o no está cifrada.' 'System drive is not encrypted.')) }
                if ([int]$vol.ProtectionStatus -eq 1) { return (New-Outcome PASS ("$env:SystemDrive " + (L 'cifrada y protegida.' 'encrypted and protected.'))) }
                return (New-Outcome FAIL ("$env:SystemDrive " + (L 'sin protección de BitLocker.' 'not protected by BitLocker.')))
            }))

    $results.Add((Invoke-Check -Id 'SEC-05' -Category 'Security' -Severity 'Medium' -Reference 'CIS v8 4.1' `
                -Name (L 'Arranque seguro (Secure Boot) habilitado' 'Secure Boot enabled') `
                -Remediation (L 'Habilita Secure Boot en la configuración UEFI del equipo.' 'Enable Secure Boot in the UEFI settings.') `
                -Test {
                $secureBoot = $null
                try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop }
                catch {
                    if ($_.Exception -is [System.PlatformNotSupportedException] -or $_.Exception.Message -match 'not supported|no se admite|no es compatible') {
                        return (New-Outcome WARN (L 'El equipo arranca en modo BIOS heredado; Secure Boot no está disponible.' 'Legacy BIOS boot; Secure Boot unavailable.'))
                    }
                    throw
                }
                if ($secureBoot) { return (New-Outcome PASS (L 'Secure Boot activo.' 'Secure Boot enabled.')) }
                return (New-Outcome FAIL (L 'UEFI con Secure Boot desactivado.' 'UEFI with Secure Boot disabled.'))
            }))

    $results.Add((Invoke-Check -Id 'SEC-06' -Category 'Security' -Severity 'Low' -Reference 'CIS v8 4.1' `
                -Name (L 'Chip TPM presente y listo' 'TPM present and ready') `
                -Remediation (L 'Habilita el TPM (fTPM / PTT) en la configuración UEFI.' 'Enable TPM (fTPM / PTT) in UEFI.') `
                -Test {
                $tpm = Get-Tpm -ErrorAction Stop
                if ($tpm.TpmPresent -and $tpm.TpmReady) { return (New-Outcome PASS (L 'TPM presente y listo.' 'TPM present and ready.')) }
                if ($tpm.TpmPresent) { return (New-Outcome WARN (L 'TPM presente pero no listo para usarse.' 'TPM present but not ready.')) }
                return (New-Outcome WARN (L 'No se detectó TPM.' 'No TPM detected.'))
            }))

    # ---------------- Parches ----------------
    $results.Add((Invoke-Check -Id 'PAT-01' -Category 'Patching' -Severity 'High' -Reference 'CIS v8 7.3' `
                -Name (L 'Actualizaciones de Windows recientes' 'Recent Windows updates') `
                -Remediation (L 'Instala las actualizaciones pendientes desde Windows Update y reinicia.' 'Install pending updates from Windows Update and reboot.') `
                -Test {
                $dates = New-Object System.Collections.Generic.List[datetime]
                try {
                    $session = New-Object -ComObject Microsoft.Update.Session
                    $searcher = $session.CreateUpdateSearcher()
                    $total = $searcher.GetTotalHistoryCount()
                    if ($total -gt 0) {
                        $history = $searcher.QueryHistory(0, [Math]::Min($total, 100))
                        foreach ($h in $history) {
                            # ResultCode 2 = correcto, Operation 1 = instalación
                            if ($h.ResultCode -eq 2 -and $h.Operation -eq 1 -and $h.Title -notmatch 'Defender|antimalware|Security Intelligence|inteligencia de seguridad') {
                                $dates.Add(([datetime]$h.Date).ToLocalTime())
                            }
                        }
                    }
                }
                catch { }
                foreach ($hf in @(Get-HotFix -ErrorAction SilentlyContinue)) {
                    if ($hf.InstalledOn) { $dates.Add([datetime]$hf.InstalledOn) }
                }
                if ($dates.Count -eq 0) { return (New-Outcome FAIL (L 'No se encontró historial de actualizaciones instaladas.' 'No installed update history found.')) }
                $last = ($dates | Sort-Object -Descending | Select-Object -First 1)
                $days = [int]((Get-Date) - $last).TotalDays
                $d = (L "Última actualización: $($last.ToString('yyyy-MM-dd')) (hace $days días); máximo: $($b.MaxDaysSinceLastUpdate)." "Last update: $($last.ToString('yyyy-MM-dd')) ($days days ago); maximum: $($b.MaxDaysSinceLastUpdate).")
                if ($days -le [int]$b.MaxDaysSinceLastUpdate) { return (New-Outcome PASS $d) }
                return (New-Outcome FAIL $d)
            }))

    $results.Add((Invoke-Check -Id 'PAT-02' -Category 'Patching' -Severity 'Medium' -Reference 'CIS v8 7.3' `
                -Name (L 'Sin reinicio pendiente por actualizaciones' 'No pending reboot') `
                -Remediation (L 'Reinicia el equipo para terminar de aplicar las actualizaciones.' 'Reboot to finish applying updates.') `
                -Test {
                $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
                if ($pending) { return (New-Outcome WARN (L 'Hay un reinicio pendiente.' 'A reboot is pending.')) }
                return (New-Outcome PASS (L 'No hay reinicios pendientes.' 'No pending reboot.'))
            }))

    # ---------------- Cuentas ----------------
    $results.Add((Invoke-Check -Id 'ACC-01' -Category 'Accounts' -Severity 'High' -Reference 'CIS v8 5.4' `
                -Name (L 'Administradores locales autorizados' 'Authorized local administrators only') `
                -Remediation (L 'Quita los privilegios de administrador a las cuentas de uso diario; usa una cuenta de soporte dedicada y agrégala a AllowedLocalAdmins en la línea base.' 'Remove admin rights from daily-use accounts; use a dedicated support account listed in AllowedLocalAdmins.') `
                -Test {
                $members = @(Get-LocalAdminMembers)
                $localUsers = @{}
                foreach ($u in @(Get-LocalUser -ErrorAction SilentlyContinue)) { $localUsers[[string]$u.SID] = $u }
                $allowed = @($b.AllowedLocalAdmins)
                $unauthorized = @()
                foreach ($m in $members) {
                    if ($m.SID -match '-500$' -or $m.SID -match '-512$') { continue }          # Administrador integrado / Domain Admins
                    if ($localUsers.ContainsKey($m.SID) -and -not $localUsers[$m.SID].Enabled) { continue }  # Cuenta deshabilitada
                    $short = $m.Name.Split('\')[-1]
                    if ($allowed -contains $short -or $allowed -contains $m.Name) { continue }
                    $unauthorized += $m.Name
                }
                if ($unauthorized.Count -eq 0) {
                    return (New-Outcome PASS ((L 'Miembros del grupo: ' 'Group members: ') + (($members | ForEach-Object { $_.Name }) -join ', ')))
                }
                return (New-Outcome FAIL ((L 'Administradores no autorizados: ' 'Unauthorized administrators: ') + ($unauthorized -join ', ')))
            }))

    $results.Add((Invoke-Check -Id 'ACC-02' -Category 'Accounts' -Severity 'Medium' -Reference 'CIS v8 4.7' `
                -Name (L 'Cuenta Administrador integrada deshabilitada' 'Built-in Administrator disabled') `
                -Remediation (L 'Ejecuta: Get-LocalUser | Where-Object SID -like "*-500" | Disable-LocalUser' 'Run: Get-LocalUser | Where-Object SID -like "*-500" | Disable-LocalUser') `
                -Test {
                $admin = Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -like '*-500' }
                if ($admin -and $admin.Enabled) { return (New-Outcome FAIL ((L 'Cuenta habilitada: ' 'Enabled account: ') + $admin.Name)) }
                return (New-Outcome PASS (L 'Cuenta integrada deshabilitada.' 'Built-in account disabled.'))
            }))

    $results.Add((Invoke-Check -Id 'ACC-03' -Category 'Accounts' -Severity 'Medium' -Reference 'CIS v8 4.7' `
                -Name (L 'Cuenta Invitado deshabilitada' 'Guest account disabled') `
                -Remediation (L 'Ejecuta: Get-LocalUser | Where-Object SID -like "*-501" | Disable-LocalUser' 'Run: Get-LocalUser | Where-Object SID -like "*-501" | Disable-LocalUser') `
                -Test {
                $guest = Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -like '*-501' }
                if ($guest -and $guest.Enabled) { return (New-Outcome FAIL ((L 'Cuenta habilitada: ' 'Enabled account: ') + $guest.Name)) }
                return (New-Outcome PASS (L 'Cuenta Invitado deshabilitada.' 'Guest account disabled.'))
            }))

    $results.Add((Invoke-Check -Id 'ACC-04' -Category 'Accounts' -Severity 'High' -Reference 'CIS v8 5.2' `
                -Name (L 'Política de contraseñas (longitud y complejidad)' 'Password policy (length and complexity)') `
                -Remediation (L "Configura longitud mínima de $($b.MinPasswordLength) y complejidad (secpol.msc > Directivas de cuenta, o GPO de dominio)." "Set minimum length $($b.MinPasswordLength) and complexity (secpol.msc or domain GPO).") `
                -Test {
                $pol = Get-SecurityPolicy
                $len = [int]$pol['MinimumPasswordLength']
                $cpx = [int]$pol['PasswordComplexity']
                $cpxText = $(if ($cpx -eq 1) { L 'sí' 'yes' } else { L 'no' 'no' })
                $d = (L "Longitud mínima: $len (requerido: $($b.MinPasswordLength)); complejidad: $cpxText." "Minimum length: $len (required: $($b.MinPasswordLength)); complexity: $cpxText.")
                if ($len -ge [int]$b.MinPasswordLength -and $cpx -eq 1) { return (New-Outcome PASS $d) }
                return (New-Outcome FAIL $d)
            }))

    $results.Add((Invoke-Check -Id 'ACC-05' -Category 'Accounts' -Severity 'Medium' -Reference 'CIS v8 4.10' `
                -Name (L 'Bloqueo de cuenta tras intentos fallidos' 'Account lockout after failed attempts') `
                -Remediation (L "Configura el umbral de bloqueo entre 1 y $($b.MaxLockoutThreshold) intentos." "Set the lockout threshold between 1 and $($b.MaxLockoutThreshold) attempts.") `
                -Test {
                $pol = Get-SecurityPolicy
                $th = [int]$pol['LockoutBadCount']
                if ($th -ge 1 -and $th -le [int]$b.MaxLockoutThreshold) {
                    return (New-Outcome PASS (L "Bloqueo tras $th intentos fallidos." "Lockout after $th failed attempts."))
                }
                if ($th -eq 0) { return (New-Outcome FAIL (L 'Sin bloqueo de cuenta (intentos ilimitados).' 'No account lockout (unlimited attempts).')) }
                return (New-Outcome FAIL (L "Umbral demasiado alto: $th intentos." "Threshold too high: $th attempts."))
            }))

    $results.Add((Invoke-Check -Id 'ACC-06' -Category 'Accounts' -Severity 'Medium' -Reference 'CIS v8 4.3' `
                -Name (L 'Bloqueo automático de pantalla' 'Automatic screen lock') `
                -Remediation (L "Configura el bloqueo por inactividad en $($b.MaxScreenLockSeconds) segundos o menos (GPO: Inicio de sesión interactivo: límite de inactividad del equipo)." "Set inactivity lock to $($b.MaxScreenLockSeconds) seconds or less (GPO: Interactive logon: Machine inactivity limit).") `
                -Test {
                $max = [int]$b.MaxScreenLockSeconds
                $machine = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
                if ($machine -and [int]$machine -ge 1 -and [int]$machine -le $max) {
                    return (New-Outcome PASS (L "Política del equipo: bloqueo a los $machine segundos." "Machine policy: lock after $machine seconds."))
                }
                foreach ($path in 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', 'HKCU:\Control Panel\Desktop') {
                    $active = Get-RegValue $path 'ScreenSaveActive'
                    $secure = Get-RegValue $path 'ScreenSaverIsSecure'
                    $timeout = Get-RegValue $path 'ScreenSaveTimeOut'
                    if ([string]$active -eq '1' -and [string]$secure -eq '1' -and $timeout -and [int]$timeout -le $max) {
                        return (New-Outcome PASS (L "Protector de pantalla con contraseña a los $timeout segundos (usuario actual)." "Password-protected screensaver after $timeout seconds (current user)."))
                    }
                }
                return (New-Outcome FAIL (L 'No hay bloqueo automático de pantalla dentro del límite.' 'No automatic screen lock within the limit.'))
            }))

    $results.Add((Invoke-Check -Id 'ACC-07' -Category 'Accounts' -Severity 'High' -Reference 'CIS v8 5.2' `
                -Name (L 'Sin inicio de sesión automático ni contraseña guardada en el registro' 'No auto-logon or stored password in registry') `
                -Remediation (L 'Elimina AutoAdminLogon y DefaultPassword en HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon.' 'Remove AutoAdminLogon and DefaultPassword from the Winlogon key.') `
                -Test {
                $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                $auto = Get-RegValue $key 'AutoAdminLogon'
                $storedPassword = Get-RegValue $key 'DefaultPassword'
                if ($null -ne $storedPassword -and [string]$storedPassword -ne '') { return (New-Outcome FAIL (L 'Hay una contraseña guardada en texto plano en el registro (DefaultPassword).' 'A plaintext password is stored in the registry (DefaultPassword).')) }
                if ([string]$auto -eq '1') { return (New-Outcome FAIL (L 'El inicio de sesión automático está activado.' 'Auto-logon is enabled.')) }
                return (New-Outcome PASS (L 'Inicio de sesión automático desactivado.' 'Auto-logon disabled.'))
            }))

    # ---------------- Red ----------------
    $results.Add((Invoke-Check -Id 'NET-01' -Category 'Network' -Severity 'High' -Reference 'CIS v8 4.8' `
                -Name (L 'SMBv1 deshabilitado' 'SMBv1 disabled') `
                -Remediation (L 'Ejecuta: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' 'Run: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force') `
                -Test {
                $cfg = Get-SmbServerConfiguration -ErrorAction Stop
                if ($cfg.EnableSMB1Protocol) { return (New-Outcome FAIL (L 'SMBv1 está habilitado (protocolo explotado por WannaCry).' 'SMBv1 is enabled (protocol exploited by WannaCry).')) }
                return (New-Outcome PASS (L 'SMBv1 deshabilitado.' 'SMBv1 disabled.'))
            }))

    $results.Add((Invoke-Check -Id 'NET-02' -Category 'Network' -Severity 'Medium' -Reference 'CIS v8 4.1' `
                -Name (L 'Escritorio remoto deshabilitado o protegido con NLA' 'Remote Desktop disabled or protected with NLA') `
                -Remediation (L 'Desactiva el Escritorio remoto o exige Autenticación a nivel de red (NLA).' 'Disable Remote Desktop or require Network Level Authentication.') `
                -Test {
                $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
                if ($null -eq $deny -or [int]$deny -eq 1) { return (New-Outcome PASS (L 'Escritorio remoto deshabilitado.' 'Remote Desktop disabled.')) }
                $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
                if ([int]$nla -eq 1) { return (New-Outcome WARN (L 'Escritorio remoto habilitado con NLA. Confirma que está autorizado.' 'Remote Desktop enabled with NLA. Confirm it is authorized.')) }
                return (New-Outcome FAIL (L 'Escritorio remoto habilitado sin NLA.' 'Remote Desktop enabled without NLA.'))
            }))

    $results.Add((Invoke-Check -Id 'NET-03' -Category 'Network' -Severity 'Medium' -Reference 'CIS v8 3.3' `
                -Name (L 'Sin carpetas compartidas abiertas a Todos' 'No shares open to Everyone') `
                -Remediation (L 'Quita el permiso de "Todos" en las carpetas compartidas y da acceso solo a grupos específicos.' 'Remove "Everyone" from shares and grant access to specific groups only.') `
                -Test {
                $everyone = (New-Object Security.Principal.SecurityIdentifier('S-1-1-0')).Translate([Security.Principal.NTAccount]).Value
                $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Name -ne 'print$' })
                $open = @()
                foreach ($s in $shares) {
                    $acl = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)
                    if ($acl | Where-Object { $_.AccountName -eq $everyone -and [string]$_.AccessControlType -eq 'Allow' }) { $open += $s.Name }
                }
                if ($open.Count -gt 0) { return (New-Outcome WARN ((L 'Compartidas abiertas a Todos: ' 'Shares open to Everyone: ') + ($open -join ', '))) }
                return (New-Outcome PASS ((L 'Carpetas compartidas revisadas: ' 'Shares reviewed: ') + $shares.Count))
            }))

    # ---------------- Sistema ----------------
    $results.Add((Invoke-Check -Id 'SYS-01' -Category 'System' -Severity 'High' -Reference 'CIS v8 4.1' `
                -Name (L 'Control de cuentas de usuario (UAC) activo' 'User Account Control (UAC) enabled') `
                -Remediation (L 'Activa UAC y evita la opción "No notificarme nunca".' 'Enable UAC and avoid "Never notify".') `
                -Test {
                $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                $lua = Get-RegValue $key 'EnableLUA'
                $prompt = Get-RegValue $key 'ConsentPromptBehaviorAdmin'
                if ([int]$lua -eq 1 -and [int]$prompt -ne 0) { return (New-Outcome PASS (L 'UAC activo con solicitud de consentimiento.' 'UAC enabled with consent prompt.')) }
                if ([int]$lua -eq 1) { return (New-Outcome FAIL (L 'UAC activo pero sin solicitud para administradores ("No notificarme nunca").' 'UAC enabled but never prompts administrators.')) }
                return (New-Outcome FAIL (L 'UAC desactivado.' 'UAC disabled.'))
            }))

    $results.Add((Invoke-Check -Id 'SYS-02' -Category 'System' -Severity 'Low' -Reference 'CIS v8 10.3' `
                -Name (L 'Reproducción automática (AutoRun) deshabilitada' 'AutoRun disabled') `
                -Remediation (L 'GPO: Plantillas administrativas > Directivas de reproducción automática > Desactivar reproducción automática: Todas las unidades.' 'GPO: Turn off AutoPlay on all drives.') `
                -Test {
                $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                $types = Get-RegValue $key 'NoDriveTypeAutoRun'
                $noAuto = Get-RegValue $key 'NoAutorun'
                if ([int]$types -eq 255 -or [int]$noAuto -eq 1) { return (New-Outcome PASS (L 'AutoRun deshabilitado para todas las unidades.' 'AutoRun disabled for all drives.')) }
                return (New-Outcome WARN (L 'AutoRun no está deshabilitado por política.' 'AutoRun is not disabled by policy.'))
            }))

    $results.Add((Invoke-Check -Id 'SYS-03' -Category 'System' -Severity 'Medium' -Reference (L 'Política interna' 'Internal policy') `
                -Name (L 'Almacenamiento USB según política' 'USB storage per policy') `
                -Remediation (L 'Bloquea el almacenamiento USB por GPO (Sistema > Acceso de almacenamiento extraíble > Todas las clases: denegar todo el acceso).' 'Block USB storage via GPO (Removable Storage Access > All classes: Deny all access).') `
                -Test {
                $start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start'
                $denyAll = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' 'Deny_All'
                $blocked = ([int]$start -eq 4) -or ([int]$denyAll -eq 1)
                $state = $(if ($blocked) { L 'bloqueado' 'blocked' } else { L 'permitido' 'allowed' })
                if ($b.BlockUsbStorage) {
                    if ($blocked) { return (New-Outcome PASS (L 'Almacenamiento USB bloqueado, como exige la política.' 'USB storage blocked as required.')) }
                    return (New-Outcome FAIL (L 'La política exige bloquear USB y está permitido.' 'Policy requires blocking USB and it is allowed.'))
                }
                return (New-Outcome INFO (L "Almacenamiento USB $state (la línea base no exige bloqueo)." "USB storage $state (baseline does not require blocking)."))
            }))

    # ---------------- Software ----------------
    $results.Add((Invoke-Check -Id 'SW-01' -Category 'Software' -Severity 'High' -Reference 'CIS v8 2.3' `
                -Name (L 'Sin software no autorizado' 'No unauthorized software') `
                -Remediation (L 'Desinstala el software no autorizado o solicita su aprobación formal.' 'Uninstall unauthorized software or request formal approval.') `
                -Test {
                $software = Get-InstalledSoftware
                $found = @()
                foreach ($pattern in @($b.BlockedSoftware)) {
                    $found += @($software | Where-Object { $_.Name -like "*$pattern*" } | ForEach-Object { $_.Name })
                }
                $found = @($found | Sort-Object -Unique)
                if ($found.Count -gt 0) { return (New-Outcome FAIL ((L 'Encontrado: ' 'Found: ') + ($found -join ', '))) }
                return (New-Outcome PASS ((L 'Revisados ' 'Reviewed ') + $software.Count + (L ' programas contra la lista de bloqueo.' ' programs against the blocklist.')))
            }))

    $results.Add((Invoke-Check -Id 'SW-02' -Category 'Software' -Severity 'Medium' -Reference 'CIS v8 2.1' `
                -Name (L 'Software corporativo requerido instalado' 'Required corporate software installed') `
                -Remediation (L 'Instala el software faltante (por ejemplo, agentes de inventario o de seguridad).' 'Install the missing software (e.g. inventory or security agents).') `
                -Test {
                $required = @($b.RequiredSoftware)
                if ($required.Count -eq 0) { return (New-Outcome INFO (L 'La línea base no define software requerido.' 'Baseline defines no required software.')) }
                $software = Get-InstalledSoftware
                $missing = @($required | Where-Object { $req = $_; -not ($software | Where-Object { $_.Name -like "*$req*" }) })
                if ($missing.Count -gt 0) { return (New-Outcome FAIL ((L 'Falta: ' 'Missing: ') + ($missing -join ', '))) }
                return (New-Outcome PASS ((L 'Instalado: ' 'Installed: ') + ($required -join ', ')))
            }))

    # ---------------- Hábitos de usuario ----------------
    $results.Add((Invoke-Check -Id 'BHV-01' -Category 'Behavior' -Severity 'Medium' -Reference 'CIS v8 14.3' `
                -Name (L 'Sin archivos de contraseñas en texto plano' 'No plaintext password files') `
                -Remediation (L 'Mueve esas credenciales a un gestor de contraseñas aprobado y borra los archivos. Refuerza la capacitación del usuario.' 'Move credentials to an approved password manager, delete the files and retrain the user.') `
                -Test {
                $namePattern = 'passw|contrase|clave|credencial|credential'
                $extensions = '.txt', '.csv', '.xlsx', '.xls', '.docx', '.doc', '.rtf', '.odt', '.ods'
                $skip = 'Public', 'Default', 'Default User', 'All Users', 'Público'
                $hits = @()
                foreach ($userDir in @(Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue | Where-Object { $skip -notcontains $_.Name })) {
                    foreach ($sub in 'Desktop', 'Documents', 'Downloads', 'OneDrive') {
                        $root = Join-Path $userDir.FullName $sub
                        if (-not (Test-Path -LiteralPath $root)) { continue }
                        $hits += @(Get-ChildItem -LiteralPath $root -File -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                                Where-Object { $_.Name -match $namePattern -and $extensions -contains $_.Extension.ToLower() } |
                                ForEach-Object { $_.FullName })
                    }
                }
                $hits = @($hits | Sort-Object -Unique)
                if ($hits.Count -gt 0) {
                    $shown = ($hits | Select-Object -First 5) -join '; '
                    $more = $(if ($hits.Count -gt 5) { (L " y $($hits.Count - 5) más" " and $($hits.Count - 5) more") } else { '' })
                    return (New-Outcome WARN ((L "Posibles archivos de contraseñas ($($hits.Count)): " "Possible password files ($($hits.Count)): ") + $shown + $more))
                }
                return (New-Outcome PASS (L 'No se encontraron archivos sospechosos en Escritorio, Documentos, Descargas ni OneDrive.' 'No suspicious files in Desktop, Documents, Downloads or OneDrive.'))
            }))

    $results.Add((Invoke-Check -Id 'BHV-02' -Category 'Behavior' -Severity 'Low' -Reference 'CIS v8 7.3' `
                -Name (L 'El equipo se reinicia con regularidad' 'Device is rebooted regularly') `
                -Remediation (L 'Pide al usuario reiniciar al menos una vez por semana para aplicar parches.' 'Ask the user to reboot at least weekly to apply patches.') `
                -Test {
                $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
                $days = [int]((Get-Date) - $boot).TotalDays
                $d = (L "Encendido desde hace $days día(s); máximo: $($b.MaxUptimeDays). Nota: el inicio rápido no reinicia el contador al apagar." "Up for $days day(s); maximum: $($b.MaxUptimeDays). Note: Fast Startup does not reset uptime on shutdown.")
                if ($days -le [int]$b.MaxUptimeDays) { return (New-Outcome PASS $d) }
                return (New-Outcome WARN $d)
            }))

    # ---------------- Mantenimiento ----------------
    $results.Add((Invoke-Check -Id 'MNT-01' -Category 'Maintenance' -Severity 'Low' -Reference (L 'Mantenimiento preventivo' 'Preventive maintenance') `
                -Name (L 'Espacio libre suficiente en el disco del sistema' 'Enough free space on system drive') `
                -Remediation (L 'Libera espacio con el Liberador de espacio en disco o el kit de mantenimiento.' 'Free space with Disk Cleanup or the maintenance kit.') `
                -Test {
                $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction Stop
                $pct = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
                $freeGb = [math]::Round($disk.FreeSpace / 1GB, 1)
                $d = (L "Libre: $freeGb GB ($pct %); mínimo: $($b.MinFreeSpacePercent) %." "Free: $freeGb GB ($pct %); minimum: $($b.MinFreeSpacePercent) %.")
                if ($pct -ge [double]$b.MinFreeSpacePercent) { return (New-Outcome PASS $d) }
                return (New-Outcome WARN $d)
            }))

    # ---------------- Dominio ----------------
    $results.Add((Invoke-Check -Id 'DOM-01' -Category 'Domain' -Severity 'Medium' -Reference 'CIS v8 1.1' `
                -Name (L 'Membresía de dominio' 'Domain membership') `
                -Remediation (L "Une el equipo al dominio: Add-Computer -DomainName $ExpectedDomain -Restart" "Join the domain: Add-Computer -DomainName $ExpectedDomain -Restart") `
                -Test {
                $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                $current = $(if ($cs.PartOfDomain) { (L 'Dominio: ' 'Domain: ') + $cs.Domain } else { (L 'Grupo de trabajo: ' 'Workgroup: ') + $cs.Domain })
                if (-not $ExpectedDomain) { return (New-Outcome INFO $current) }
                if ($cs.PartOfDomain -and $cs.Domain -ieq $ExpectedDomain) { return (New-Outcome PASS $current) }
                return (New-Outcome FAIL ($current + (L " (esperado: $ExpectedDomain)" " (expected: $ExpectedDomain)")))
            }))

    return $results
}

#endregion

#region ---------- Inventario, veredicto y comparación ----------

function Get-Inventory {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive)
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $displayVersion = Get-RegValue $cv 'DisplayVersion'
    $ubr = Get-RegValue $cv 'UBR'
    $ips = @()
    try {
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
                ForEach-Object { $_.IPAddress })
    }
    catch { }
    return [ordered]@{
        Hostname     = $env:COMPUTERNAME
        Manufacturer = [string]$cs.Manufacturer
        Model        = [string]$cs.Model
        SerialNumber = [string]$bios.SerialNumber
        CPU          = ([string]$cpu.Name).Trim()
        RamGB        = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        OS           = [string]$os.Caption
        OSVersion    = ('{0} ({1}.{2})' -f $displayVersion, $os.BuildNumber, $ubr)
        InstallDate  = ([datetime]$os.InstallDate).ToString('yyyy-MM-dd')
        LastBoot     = ([datetime]$os.LastBootUpTime).ToString('yyyy-MM-dd HH:mm')
        SystemDiskGB = [math]::Round($disk.Size / 1GB, 0)
        IPv4         = ($ips -join ', ')
        CurrentUser  = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        Software     = @(Get-InstalledSoftware)
    }
}

function Get-Verdict {
    param($Results)
    $scored = @($Results | Where-Object { $_.Status -ne 'INFO' })
    $pass = @($scored | Where-Object { $_.Status -eq 'PASS' }).Count
    $score = $(if ($scored.Count -gt 0) { [math]::Round(($pass / $scored.Count) * 100, 0) } else { 0 })
    $criticalFail = @($Results | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count
    $issues = @($Results | Where-Object { $_.Status -in 'FAIL', 'WARN', 'ERROR' }).Count
    $code = $(if ($criticalFail -gt 0) { 'NOT_CERTIFIED' } elseif ($issues -gt 0) { 'CERTIFIED_WITH_OBSERVATIONS' } else { 'CERTIFIED' })
    return [ordered]@{
        Code        = $code
        Label       = (Get-Label 'Verdict' $code)
        Score       = $score
        Pass        = $pass
        Fail        = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
        Warn        = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
        Error       = @($Results | Where-Object { $_.Status -eq 'ERROR' }).Count
        Info        = @($Results | Where-Object { $_.Status -eq 'INFO' }).Count
        CriticalFail = $criticalFail
    }
}

function Compare-Certification {
    param($Results, $Verdict, [string]$PreviousPath, [string]$CurrentHost)
    $prev = Get-Content -LiteralPath $PreviousPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $rank = @{ ERROR = 0; FAIL = 1; WARN = 2; INFO = 3; PASS = 4 }
    $prevById = @{}
    foreach ($r in @($prev.Results)) { $prevById[[string]$r.Id] = $r }
    $changes = @()
    foreach ($r in $Results) {
        if (-not $prevById.ContainsKey($r.Id)) { continue }
        $before = [string]$prevById[$r.Id].Status
        if ($before -eq $r.Status) { continue }
        $trend = $(if ($rank[$r.Status] -gt $rank[$before]) { 'IMPROVED' } else { 'DEGRADED' })
        $changes += [pscustomobject]@{
            Id          = $r.Id
            Name        = $r.Name
            Before      = $before
            BeforeLabel = (Get-Label 'Status' $before)
            After       = $r.Status
            AfterLabel  = $r.StatusLabel
            Trend       = $trend
            TrendLabel  = $(if ($trend -eq 'IMPROVED') { L 'Mejoró' 'Improved' } else { L 'Empeoró' 'Degraded' })
        }
    }
    return [ordered]@{
        PreviousFile    = (Split-Path -Leaf $PreviousPath)
        PreviousDate    = [string]$prev.Metadata.Date
        PreviousVerdict = (Get-Label 'Verdict' ([string]$prev.Verdict.Code))
        PreviousScore   = [int]$prev.Verdict.Score
        SameHost        = ([string]$prev.Inventory.Hostname -eq $CurrentHost)
        Improved        = @($changes | Where-Object { $_.Trend -eq 'IMPROVED' }).Count
        Degraded        = @($changes | Where-Object { $_.Trend -eq 'DEGRADED' }).Count
        Changes         = $changes
    }
}

#endregion

#region ---------- Anonimización / Anonymization ----------

function Get-ShortHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.ToUpperInvariant()))
        return (($bytes[0..2] | ForEach-Object { $_.ToString('X2') }) -join '')
    }
    finally { $sha.Dispose() }
}

function Protect-Report {
    # Reemplaza datos identificables por marcadores estables (mismo equipo = mismo marcador)
    param($Report)
    $map = [ordered]@{}
    $hostName = [string]$Report.Inventory.Hostname
    $map[$hostName] = 'EQUIPO-' + (Get-ShortHash $hostName)
    if ($Report.Inventory.SerialNumber) { $map[[string]$Report.Inventory.SerialNumber] = 'SERIE-OCULTA' }
    $i = 1
    $names = @()
    $names += @(Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $names += @(Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $names += $env:USERNAME, $env:USERDOMAIN
    $generic = 'Public', 'Default', 'Default User', 'All Users', 'Administrator', 'Administrador', 'Guest', 'Invitado', 'DefaultAccount', 'WDAGUtilityAccount', 'Público'
    foreach ($n in ($names | Where-Object { $_ -and $generic -notcontains $_ } | Sort-Object Length -Descending -Unique)) {
        if (-not $map.Contains($n) -and $n.Length -ge 3) { $map[$n] = "usuario$i"; $i++ }
    }
    $scrub = {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return $Text }
        foreach ($k in $map.Keys) { $Text = [regex]::Replace($Text, [regex]::Escape($k), $map[$k], 'IgnoreCase') }
        return [regex]::Replace($Text, '\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b', '$1.$2.x.x')
    }
    foreach ($r in $Report.Results) {
        $r.Detail = & $scrub $r.Detail
        $r.Name = & $scrub $r.Name
    }
    foreach ($key in @($Report.Inventory.Keys)) {
        if ($key -eq 'Software') { continue }
        $Report.Inventory[$key] = & $scrub ([string]$Report.Inventory[$key])
    }
    $Report.Metadata.Technician = & $scrub $Report.Metadata.Technician
    $Report.Metadata.Anonymized = $true
    return $Report
}

#endregion

#region ---------- Reportes / Reports ----------

function New-HtmlReport {
    param($Report)
    $v = $Report.Verdict
    $inv = $Report.Inventory
    $meta = $Report.Metadata
    $badge = switch ($v.Code) { 'CERTIFIED' { 'ok' } 'CERTIFIED_WITH_OBSERVATIONS' { 'warn' } default { 'bad' } }
    $sb = New-Object System.Text.StringBuilder

    $invLabels = [ordered]@{
        Hostname     = (L 'Equipo' 'Hostname')
        Manufacturer = (L 'Fabricante' 'Manufacturer')
        Model        = (L 'Modelo' 'Model')
        SerialNumber = (L 'Número de serie' 'Serial number')
        CPU          = 'CPU'
        RamGB        = (L 'RAM (GB)' 'RAM (GB)')
        OS           = (L 'Sistema operativo' 'Operating system')
        OSVersion    = (L 'Versión' 'Version')
        InstallDate  = (L 'Instalado el' 'Installed on')
        LastBoot     = (L 'Último arranque' 'Last boot')
        SystemDiskGB = (L 'Disco del sistema (GB)' 'System disk (GB)')
        IPv4         = 'IPv4'
        CurrentUser  = (L 'Usuario que ejecutó' 'Run by')
    }

    [void]$sb.AppendLine('<!doctype html>')
    [void]$sb.AppendLine(('<html lang="{0}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' -f $script:Lang))
    [void]$sb.AppendLine(('<title>{0} - {1}</title>' -f (L 'Certificación de equipo' 'Endpoint certification'), (ConvertTo-HtmlText $inv.Hostname)))
    [void]$sb.AppendLine(@'
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d232b;--muted:#5d6876;--line:#dfe3e8;--ok:#127a3e;--okbg:#e3f4e9;--warn:#8a5a00;--warnbg:#fdf1d6;--bad:#b42318;--badbg:#fde5e2;--info:#1f5fa8;--infobg:#e3eefb;--err:#7a2e8a;--errbg:#f3e4f6}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--ink:#e6e9ee;--muted:#9aa4b1;--line:#2e343d;--okbg:#14321f;--ok:#6fd49a;--warnbg:#3a2e10;--warn:#f2c35b;--badbg:#3d1714;--bad:#ff8a80;--infobg:#132a45;--info:#8bbcf2;--errbg:#33193a;--err:#d9a3e6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.hero{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center}
.badge{display:inline-block;padding:8px 14px;border-radius:8px;font-weight:700;letter-spacing:.3px}
.ok{background:var(--okbg);color:var(--ok)}.warn{background:var(--warnbg);color:var(--warn)}.bad{background:var(--badbg);color:var(--bad)}.info{background:var(--infobg);color:var(--info)}.err{background:var(--errbg);color:var(--err)}
.score{font-size:40px;font-weight:700;text-align:right}.stats{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.pill{padding:3px 10px;border-radius:999px;font-size:13px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:13px;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:none}td:first-child{white-space:nowrap}.kv td:first-child{width:220px;color:var(--muted)}
.tag{white-space:nowrap;font-size:12px;font-weight:700;padding:2px 8px;border-radius:6px}
.fix{color:var(--muted);font-size:13px;margin-top:4px}.wrap{overflow-x:auto}
details{margin-top:12px}summary{cursor:pointer;color:var(--info)}footer{margin-top:32px;font-size:13px;color:var(--muted)}
@media (max-width:640px){.hero{grid-template-columns:1fr}.score{text-align:left}.kv td:first-child{width:auto}}
</style></head><body><main>
'@)

    [void]$sb.AppendLine(('<h1>{0}</h1>' -f (L 'Reporte de certificación de equipo' 'Endpoint certification report')))
    [void]$sb.AppendLine(('<p class="muted">{0} {1} · {2} {3} · {4} {5}</p>' -f (L 'Fecha:' 'Date:'), (ConvertTo-HtmlText $meta.Date), (L 'Técnico:' 'Technician:'), (ConvertTo-HtmlText $meta.Technician), (L 'Línea base:' 'Baseline:'), (ConvertTo-HtmlText $meta.BaselineSource)))

    [void]$sb.AppendLine('<div class="card hero"><div>')
    [void]$sb.AppendLine(('<span class="badge {0}">{1}</span>' -f $badge, (ConvertTo-HtmlText $v.Label)))
    [void]$sb.AppendLine('<div class="stats">')
    [void]$sb.AppendLine(('<span class="pill ok">{0}: {1}</span>' -f (Get-Label 'Status' 'PASS'), $v.Pass))
    [void]$sb.AppendLine(('<span class="pill bad">{0}: {1}</span>' -f (Get-Label 'Status' 'FAIL'), $v.Fail))
    [void]$sb.AppendLine(('<span class="pill warn">{0}: {1}</span>' -f (Get-Label 'Status' 'WARN'), $v.Warn))
    [void]$sb.AppendLine(('<span class="pill err">{0}: {1}</span>' -f (Get-Label 'Status' 'ERROR'), $v.Error))
    [void]$sb.AppendLine(('<span class="pill info">{0}: {1}</span>' -f (Get-Label 'Status' 'INFO'), $v.Info))
    [void]$sb.AppendLine('</div>')
    if ($v.CriticalFail -gt 0) {
        [void]$sb.AppendLine(('<p class="muted">{0}</p>' -f (L "Hay $($v.CriticalFail) control(es) de severidad alta sin cumplir; el equipo no se puede entregar hasta corregirlos." "$($v.CriticalFail) high-severity control(s) failed; the device cannot be released until fixed.")))
    }
    if (-not $meta.RunAsAdmin) {
        [void]$sb.AppendLine(('<p class="muted">{0}</p>' -f (L 'Ejecutado sin privilegios de administrador: algunos controles no se pudieron evaluar.' 'Run without administrator rights: some controls could not be evaluated.')))
    }
    [void]$sb.AppendLine(('</div><div class="score">{0}%<div class="muted" style="font-size:13px;font-weight:400">{1}</div></div></div>' -f $v.Score, (L 'controles cumplidos' 'controls passed')))

    if ($Report.Comparison) {
        $c = $Report.Comparison
        [void]$sb.AppendLine(('<h2>{0}</h2>' -f (L 'Recertificación: comparación con la certificación anterior' 'Recertification: comparison with previous run')))
        [void]$sb.AppendLine(('<p>{0} <strong>{1}</strong> ({2}) · {3} <strong>{4}%</strong> → <strong>{5}%</strong> · {6} {7} · {8} {9}</p>' -f `
                    (L 'Anterior:' 'Previous:'), (ConvertTo-HtmlText $c.PreviousVerdict), (ConvertTo-HtmlText $c.PreviousDate), (L 'Puntaje' 'Score'), $c.PreviousScore, $v.Score, (L 'Mejoraron:' 'Improved:'), $c.Improved, (L 'Empeoraron:' 'Degraded:'), $c.Degraded))
        if (-not $c.SameHost) {
            [void]$sb.AppendLine(('<p class="badge warn">{0}</p>' -f (L 'Atención: el reporte anterior es de otro equipo.' 'Warning: the previous report is from a different device.')))
        }
        if (@($c.Changes).Count -gt 0) {
            [void]$sb.AppendLine(('<div class="wrap"><table><thead><tr><th>ID</th><th>{0}</th><th>{1}</th><th>{2}</th><th>{3}</th></tr></thead><tbody>' -f (L 'Control' 'Control'), (L 'Antes' 'Before'), (L 'Ahora' 'Now'), (L 'Tendencia' 'Trend')))
            foreach ($ch in $c.Changes) {
                $cls = $(if ($ch.Trend -eq 'IMPROVED') { 'ok' } else { 'bad' })
                [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td><span class="tag {4}">{5}</span></td></tr>' -f $ch.Id, (ConvertTo-HtmlText $ch.Name), $ch.BeforeLabel, $ch.AfterLabel, $cls, $ch.TrendLabel))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
        }
        else {
            [void]$sb.AppendLine(('<p class="muted">{0}</p>' -f (L 'Ningún control cambió de estado.' 'No control changed status.')))
        }
    }

    [void]$sb.AppendLine(('<h2>{0}</h2>' -f (L 'Ficha del equipo' 'Device record')))
    [void]$sb.AppendLine('<table class="kv"><tbody>')
    foreach ($k in $invLabels.Keys) {
        [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f $invLabels[$k], (ConvertTo-HtmlText $inv[$k])))
    }
    [void]$sb.AppendLine('</tbody></table>')

    [void]$sb.AppendLine(('<h2>{0}</h2>' -f (L 'Resultados por control' 'Results by control')))
    [void]$sb.AppendLine(('<div class="wrap"><table><thead><tr><th>ID</th><th>{0}</th><th>{1}</th><th>{2}</th><th>{3}</th><th>{4}</th></tr></thead><tbody>' -f `
                (L 'Categoría' 'Category'), (L 'Control y hallazgo' 'Control and finding'), (L 'Severidad' 'Severity'), (L 'Estado' 'Status'), (L 'Referencia' 'Reference')))
    $order = @{ FAIL = 0; ERROR = 1; WARN = 2; PASS = 3; INFO = 4 }
    $sevOrder = @{ High = 0; Medium = 1; Low = 2 }
    foreach ($r in ($Report.Results | Sort-Object @{ Expression = { $order[$_.Status] } }, @{ Expression = { $sevOrder[$_.Severity] } }, Id)) {
        $cls = switch ($r.Status) { 'PASS' { 'ok' } 'FAIL' { 'bad' } 'WARN' { 'warn' } 'ERROR' { 'err' } default { 'info' } }
        $fix = $(if ($r.Remediation) { '<div class="fix">' + (L 'Corrección: ' 'Fix: ') + (ConvertTo-HtmlText $r.Remediation) + '</div>' } else { '' })
        [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td><strong>{2}</strong><div>{3}</div>{4}</td><td>{5}</td><td><span class="tag {6}">{7}</span></td><td>{8}</td></tr>' -f `
                    $r.Id, (ConvertTo-HtmlText $r.CategoryLabel), (ConvertTo-HtmlText $r.Name), (ConvertTo-HtmlText $r.Detail), $fix, $r.SeverityLabel, $cls, $r.StatusLabel, (ConvertTo-HtmlText $r.Reference)))
    }
    [void]$sb.AppendLine('</tbody></table></div>')

    $software = @($inv.Software)
    [void]$sb.AppendLine(('<details><summary>{0} ({1})</summary><div class="wrap"><table><thead><tr><th>{2}</th><th>{3}</th><th>{4}</th></tr></thead><tbody>' -f `
                (L 'Software instalado' 'Installed software'), $software.Count, (L 'Nombre' 'Name'), (L 'Versión' 'Version'), (L 'Editor' 'Publisher')))
    foreach ($s in $software) {
        [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-HtmlText $s.Name), (ConvertTo-HtmlText $s.Version), (ConvertTo-HtmlText $s.Publisher)))
    }
    [void]$sb.AppendLine('</tbody></table></div></details>')

    [void]$sb.AppendLine(('<footer>{0} v{1} · {2}</footer>' -f 'Invoke-EndpointCertification', $script:Version, (L 'Criterio: un control de severidad alta sin cumplir impide la certificación; cualquier otro hallazgo la deja con observaciones.' 'Rule: any failed high-severity control blocks certification; other findings result in observations.')))
    [void]$sb.AppendLine('</main></body></html>')
    return $sb.ToString()
}

function Export-Reports {
    param($Report, [string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { New-Item -ItemType Directory -Path $Folder -Force | Out-Null }
    # Ruta absoluta: los métodos .NET no conocen la carpeta actual de PowerShell
    $Folder = (Resolve-Path -LiteralPath $Folder).ProviderPath
    $safeHost = ([string]$Report.Inventory.Hostname) -replace '[^A-Za-z0-9_-]', '_'
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $base = Join-Path $Folder ('cert_{0}_{1}' -f $safeHost, $stamp)

    $json = $Report | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText("$base.json", $json, (New-Object System.Text.UTF8Encoding($false)))

    $Report.Results | Select-Object Id, CategoryLabel, Name, SeverityLabel, StatusLabel, Detail, Remediation, Reference |
        Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8

    $html = New-HtmlReport -Report $Report
    [System.IO.File]::WriteAllText("$base.html", $html, (New-Object System.Text.UTF8Encoding($true)))

    return [pscustomobject]@{ Html = "$base.html"; Json = "$base.json"; Csv = "$base.csv" }
}

#endregion

#region ---------- Principal / Main ----------

function Invoke-Main {
    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        Write-Error (L 'Este script solo funciona en Windows. Para Linux o macOS usa certify-endpoint.sh.' 'This script runs on Windows only. Use certify-endpoint.sh on Linux or macOS.')
        return 3
    }

    $isAdmin = Test-IsAdmin
    Write-Host ''
    Write-Host (L '=== Certificación de equipo ===' '=== Endpoint certification ===') -ForegroundColor Cyan
    if (-not $isAdmin) {
        Write-Warning (L 'No estás ejecutando como administrador. Algunos controles quedarán en ERROR.' 'Not running as administrator. Some controls will report ERROR.')
    }

    $baseline = Get-Baseline -Path $BaselinePath
    Write-Host ((L 'Línea base: ' 'Baseline: ') + $script:BaselineSource) -ForegroundColor DarkGray
    Write-Host ''

    $results = @(Invoke-AllChecks -Baseline $baseline)
    $verdict = Get-Verdict -Results $results
    $inventory = Get-Inventory

    $report = [ordered]@{
        Metadata   = [ordered]@{
            Tool           = 'Invoke-EndpointCertification'
            Version        = $script:Version
            Date           = (Get-Date).ToString('yyyy-MM-dd HH:mm')
            Technician     = $Technician
            Language       = $script:Lang
            RunAsAdmin     = $isAdmin
            BaselineSource = $script:BaselineSource
            Anonymized     = $false
        }
        Verdict    = $verdict
        Inventory  = $inventory
        Results    = $results
        Comparison = $null
    }

    if ($Anonymize) { $report = Protect-Report -Report $report }

    if ($PreviousReport) {
        if (Test-Path -LiteralPath $PreviousReport) {
            $report.Comparison = Compare-Certification -Results $results -Verdict $verdict -PreviousPath $PreviousReport -CurrentHost ([string]$report.Inventory.Hostname)
        }
        else {
            Write-Warning ((L 'No se encontró el reporte anterior: ' 'Previous report not found: ') + $PreviousReport)
        }
    }

    $files = Export-Reports -Report $report -Folder $OutputPath

    Write-Host ''
    $color = switch ($verdict.Code) { 'CERTIFIED' { 'Green' } 'CERTIFIED_WITH_OBSERVATIONS' { 'Yellow' } default { 'Red' } }
    Write-Host ((L 'Veredicto: ' 'Verdict: ') + $verdict.Label + "  ($($verdict.Score)%)") -ForegroundColor $color
    if ($report.Comparison) {
        Write-Host ((L 'Recertificación: ' 'Recertification: ') + "$($report.Comparison.PreviousScore)% -> $($verdict.Score)%  " +
            (L "mejoraron $($report.Comparison.Improved), empeoraron $($report.Comparison.Degraded)" "improved $($report.Comparison.Improved), degraded $($report.Comparison.Degraded)"))
    }
    Write-Host ((L 'Reporte HTML: ' 'HTML report: ') + $files.Html)
    Write-Host ((L 'Datos JSON:   ' 'JSON data:   ') + $files.Json)
    Write-Host ((L 'Tabla CSV:    ' 'CSV table:   ') + $files.Csv)

    if (-not $NoOpen) { try { Invoke-Item -LiteralPath $files.Html } catch { } }

    switch ($verdict.Code) { 'CERTIFIED' { return 0 } 'CERTIFIED_WITH_OBSERVATIONS' { return 1 } default { return 2 } }
}

# Permite cargar las funciones con ". .\script.ps1" para pruebas sin ejecutar la certificación
# Allows dot-sourcing for tests without running the certification
if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = 3
    try { $exitCode = Invoke-Main }
    catch {
        Write-Error $_
        $exitCode = 3
    }
    exit $exitCode
}

#endregion
