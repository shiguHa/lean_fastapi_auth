# Client ID/Secret で直接トークンを取得
# Invoke-RestMethodが自動でJSONを解釈し、オブジェクトにしてくれる
# $response = Invoke-RestMethod -Uri "http://localhost:8000/token" -Method Post -Body @{
#     grant_type    = "client_credentials"
#     client_id     = "plc-client-id"
#     client_secret = "plc-client-secret"
# }

# # 応答オブジェクトからaccess_tokenプロパティを取得
# $TOKEN = $response.access_token

# # 取得したトークンでAPIにアクセス
# Write-Host "Client Access Token: $TOKEN"

# # ヘッダー情報をハッシュテーブルで作成
# $headers = @{
#     "Authorization" = "Bearer $TOKEN"
# }

# # ボディに含めるJSONデータをハッシュテーブルで作成し、JSONに変換
# $body = @{
#     "temperature" = 25.5
#     "pressure" = 1013
# } | ConvertTo-Json

# APIを呼び出す
# Invoke-RestMethod -Uri "http://localhost:8000/plc/data" -Method Post -Headers $headers -Body $body -ContentType "application/json"

# クライアントのトークンを取得
$response = Invoke-RestMethod -Uri "http://localhost:8000/token" -Method Post -Body @{
    grant_type    = "client_credentials"
    client_id     = "plc-client-id"
    client_secret = "plc-client-secret"
}
$CLIENT_TOKEN = $response.access_token

# 共有APIにアクセス
Write-Host "`n--- Accessing /shared/info with CLIENT token ---"
Invoke-RestMethod -Uri "http://localhost:8000/shared/info" -Headers @{"Authorization"="Bearer $CLIENT_TOKEN"}