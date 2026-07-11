[CmdletBinding()]
param()

$confirmation = Read-Host 'This deletes the local relay PostgreSQL volume and all relay state. Type DELETE RELAY DATA to continue'
if ($confirmation -cne 'DELETE RELAY DATA') {
  Write-Error 'Reset cancelled. No data was deleted.'
  exit 1
}

docker compose down -v
