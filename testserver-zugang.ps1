param([switch]$ShowLogin)

$ErrorActionPreference = 'Stop'
$identity = Join-Path $env:USERPROFILE '.ssh\udm-debian-test-20261009'
$knownHosts = Join-Path $env:USERPROFILE '.ssh\known_hosts_udm_debian_test'
if (!(Test-Path -LiteralPath $identity -PathType Leaf) -or !(Test-Path -LiteralPath $knownHosts -PathType Leaf)) {
    throw 'Der eingerichtete SSH-Schluessel oder die gepinnte known_hosts-Datei fehlt.'
}
$sshArguments = @('-i', $identity, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', ('UserKnownHostsFile=' + $knownHosts),
    '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3')
if ($ShowLogin) {
    Write-Host 'Privater Testzugang: Die folgende Ausgabe enthaelt das Passwort.'
    & ssh @sshArguments 'root@5.9.102.7' 'cat /root/udm-beast-test-login.json'
} else {
    Write-Host 'SSH-Tunnel bleibt in diesem Fenster aktiv. Beenden: Strg+C.'
    Write-Host 'Im Browser oeffnen: https://127.0.0.1:18443 (lokales UniFi-Zertifikat).'
    & ssh @sshArguments '-o' 'ExitOnForwardFailure=yes' '-N' '-L' '127.0.0.1:18443:127.0.0.1:18443' 'root@5.9.102.7'
}
if ($LASTEXITCODE -ne 0) {
    throw "SSH wurde mit Fehlercode $LASTEXITCODE beendet."
}
