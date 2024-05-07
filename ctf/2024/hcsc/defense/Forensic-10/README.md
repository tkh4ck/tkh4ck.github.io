# HCSC 2024 - Forensic 10.

## Description

Have a closer look to the payload! Its goal is to help the attackers to steal sensitive and valuable data. They have found a way out, unfortunately. Can you tell the management, what was stolen? 
What was the IP address, where the data went out? And exactly when (to hours and minutes)? What was the name of the first file stolen?

(example: `hcsc{dest.IP.v.4_YYYY-MM-DD-hh-mm_First_Stolen_Filename.ext}`) 

Attention! The Time is in UTC (hours)!!!


## Metadata

- Tags: `default.asp`, `iis`, `data exfiltration`
- Points: `400`
- Number of solvers: `12`
- Filename: -

## Solution

Based on the previous challenges, the clues and the attack steps detected so far, we can conclude that the data theft was done through the IIS server.

The IIS log files are located in the `C:\inetpub\logs\LogFiles` folder. In this directory there are TXT files containing the information needed to solve the task. More specifically, `u_ex240322.log`. The first stolen sensitive file is  `/certsrv/Internal/MOCK_application_security.csv`, at `2024-03-22-00-53`, with a `GET` request from the `192.168.238.188` IP address.

```
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2024-03-22 00:52:46
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2024-03-22 00:52:46 192.168.238.129 GET /certsrv - 80 - 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 401 2 5 140
2024-03-22 00:53:06 192.168.238.129 GET /certsrv - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 301 0 0 31
2024-03-22 00:53:06 192.168.238.129 GET /certsrv/ - 80 - 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 401 2 5 0
2024-03-22 00:53:17 192.168.238.129 GET /certsrv/ - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 200 0 0 11484
2024-03-22 00:53:17 192.168.238.129 GET /certsrv/certspc.gif - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/ 200 0 0 78
2024-03-22 00:53:17 192.168.238.129 GET /favicon.ico - 80 - 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/ 404 0 2 62
2024-03-22 00:53:24 192.168.238.129 GET /certsrv/Internal - 80 - 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 401 2 5 0
2024-03-22 00:53:24 192.168.238.129 GET /certsrv/Internal - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 301 0 0 0
2024-03-22 00:53:24 192.168.238.129 GET /certsrv/Internal/ - 80 - 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 401 2 5 0
2024-03-22 00:53:24 192.168.238.129 GET /certsrv/Internal/ - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 - 200 0 0 62
2024-03-22 00:53:28 192.168.238.129 GET /certsrv/Internal/MOCK_application_security.csv - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/Internal/ 200 0 0 15
2024-03-22 00:53:32 192.168.238.129 GET /certsrv/Internal/MOCK_basic_email.csv - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/Internal/ 200 0 0 15
2024-03-22 00:53:35 192.168.238.129 GET /certsrv/Internal/MOCK_creditcard.csv - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/Internal/ 200 0 0 15
2024-03-22 00:53:38 192.168.238.129 GET /certsrv/Internal/MOCK_Investment_tender.csv - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/Internal/ 200 0 0 46
2024-03-22 00:53:41 192.168.238.129 GET /certsrv/Internal/MOCK_medical.csv - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/Internal/ 200 0 0 0
2024-03-22 00:53:44 192.168.238.129 GET /certsrv/Internal/MOCK_salary.csv - 80 hcsc\jachan 192.168.238.188 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:122.0)+Gecko/20100101+Firefox/122.0 http://192.168.238.129/certsrv/Internal/ 200 0 0 15
```

Flag: `hcsc{192.168.238.188_2024-03-22-00-53_MOCK_application_security.csv}`