# SANS Holiday Hack Challenge 2023 - Azure 101

## Description

> Help Sparkle Redberry with some Azure command line skills. Find the elf and the terminal on Christmas Island.

### Metadata

- Difficulty: 2/5
- Tags: `azure`, `az`, `cli`

## Solution

### Video

<iframe width="1280" height="720" src="https://www.youtube-nocookie.com/embed/LtHHYrNxOEw?start=500" title="SANS Holiday Hack Challenge 2023 - Azure 101" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### Write-up

> You may not know this but the Azure cli help messages are very easy to access. First, try typing: $ az help | less

```shell
az help | less
```

> Next, you've already been configured with credentials. Use 'az' and your 'account' to 'show' your current details and make sure to pipe to less ( | less )

```shell
az account show | less
```

> Excellent! Now get a list of resource groups in Azure. For more information: https://learn.microsoft.com/en-us/cli/azure/group?view=azure-cli-latest

```shell
az group list
```

> Ok, now use one of the resource groups to get a list of function apps. For more information: https://learn.microsoft.com/en-us/cli/azure/functionapp?view=azure-cli-latest Note: Some of the information returned from this command relates to other cloud assets used by Santa and his elves.

```shell
az functionapp list --resource-group northpole-rg1
```

> Find a way to list the only VM in one of the resource groups you have access to. For more information: https://learn.microsoft.com/en-us/cli/azure/vm?view=azure-cli-latest

```shell
az vm list -g northpole-rg2
```

> Find a way to invoke a run-command against the only Virtual Machine (VM) so you can RunShellScript and get a directory listing to reveal a file on the Azure VM. For more information: https://learn.microsoft.com/en-us/cli/azure/vm/run-command?view=azure-cli-latest#az-vm-run-command-invoke

```shell
az vm run-command invoke --resource-group northpole-rg2 --name NP-VM1 --scripts ls --command-id RunShellScript
```

> Great, you did it all!

> **Sparkle Redberry (Rudolph's Rest Resort)**:
*Wow, you did it!
It makes quite a bit more sense to me now. Thank you so much!
That [Azure Function App URL](https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl) you came across in the terminal looked interesting.
It might be part of that new project Alabaster has been working on with the help of ChatNPT.
Let me tell you, since he started using ChatNPT he's been introducing a lot of amazing innovation across the islands.
Knowing Alabaster, he'll be delighted to tell you all about it! I think I last saw him on Pixel island.
By the way, as part of the Azure documentation he sent the elves, Alabaster also noted that if Azure CLI tools aren't available in an Azure VM we should use the [Azure REST API](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token) instead.
I'm not really sure what that means, but I guess I know what I'll be studying up on next.*