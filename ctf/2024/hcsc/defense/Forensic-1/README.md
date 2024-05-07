# HCSC 2024 - Forensic 1.

## Description

Just to warm up your skills, you take a tour on the machine. The admin has told something about an attack in 2021. In his letter there are some details:

> “In 2021 the 5th of November, we had a successful attack from IP address 246.10.27.233, an admin account was compromised because of the lack of Two factor authentication. The attacker finally, after several attempts could answer the security question of the compromised user.”

What was that security question?

(example: `hcsc{Security question with spaces and question mark?}` - case sensitive)

## Metadata

- Tags: `strings`, `grep`, `search`
- Points: `100`
- Number of solvers: `39`
- Filename: -

## Solution

The description of the challenge states and hints: `take a tour on the machine`. We can look for the unusual folders on the file system. We can import the virtual machine and do a live investigation and we can mount the `VMDK` file too and do an offline investigation. In the `%SYSTEMDRIVE%` (`C:\`) there is an unusual folder called `MOK_DATA`. In that folder there are multiple `CSV` files. Let's `grep` for the given IP address (`246.10.27.233`). The challenge can also be solved with a single `grep` command on the full file system.

```
$ grep -ir 246.10.27.233
MOK_DATA/MOCK_application_security.csv:115,traggitt36,pE1'CKNg{ljwL'Js,admin,11/5/2021,246.10.27.233,10,What is your mother's maiden name?,non ligula pellentesque ultrices phasellus id sapien in sapien iaculis congue vivamus metus arcu adipiscing molestie hendrerit at,false
```

Flag: `hcsc{What is your mother's maiden name?}`