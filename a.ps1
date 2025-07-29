# 認可コードをセット
$CODE = "cD6BiN1MdOYJIJtSaFdNM_HaHdZvXGOrq9oqC3aN0rk"

# トークンに交換
$response = Invoke-RestMethod -Uri "http://localhost:8000/token" -Method Post -Body @{
    grant_type    = "authorization_code"
    code          = $CODE
    client_id     = "web-app-client-id"
    client_secret = "web-app-client-secret"
    redirect_uri  = "http://localhost:8000/callback"
}
$USER_TOKEN = $response.access_token

# 共有APIにアクセス
Write-Host "`n--- Accessing /shared/info with USER token ---"
Invoke-RestMethod -Uri "http://localhost:8000/shared/info" -Headers @{"Authorization"="Bearer $USER_TOKEN"}