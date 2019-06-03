mkdir C:\Working
$creds = "${INIT_CREDS}"
Write-Output $creds | Out-File -FilePath 'C:\Working\gcp-creds.json'
gcloud auth activate-service-account autoinit --key-file=C:\Working\gcp-creds.json
