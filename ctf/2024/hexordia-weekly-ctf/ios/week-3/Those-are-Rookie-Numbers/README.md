# Hexordia Weekly CTF - iOS - Week 3 - Those are Rookie Numbers

> What percentage of players were beat by PlanterPapp?

- Points: `25`

## Solution

- If we check the different screenshots and recordings on the phone, we can find out that `PlanterPapp` is the username of the owner in Call of Duty (`com.activision.callofduty.shooter`)
- We can also find this out with a simple `grep`

```
$ grep -ir planterpapp
mobile/Media/PhotoData/Caches/search/psi.sqlite
mobile/Containers/Data/Application/BF2FEA88-C397-405D-90EE-A56B2720896C/Library/Caches/cask/61555027042760/memresponse_cache/c09ad49ec917bd29de25f26e44a427abaca8ba07en_US/G1%3a38163057137705668972843833128%3a18436672011487733074
mobile/Containers/Data/Application/BF2FEA88-C397-405D-90EE-A56B2720896C/Library/Caches/cask/61555027042760/memresponse_cache/c09ad49ec917bd29de25f26e44a427abaca8ba07en_US/G1%3a38163057137705668972843833128%3a3302437956070245168
mobile/Containers/Data/Application/BF2FEA88-C397-405D-90EE-A56B2720896C/Library/Caches/cask/61555027042760/memresponse_cache/c09ad49ec917bd29de25f26e44a427abaca8ba07en_US/G1%3a38163057137705668972843833128%3a7077374228416189472
mobile/Containers/Data/Application/3690AAA8-713A-482B-92F1-3F7D3BCC73E6/Library/Preferences/com.helpshift.webchat.sdk.plist
mobile/Containers/Data/Application/3690AAA8-713A-482B-92F1-3F7D3BCC73E6/Documents/ChatCache/1192037682361107226/2023-12-20
```

- `3690AAA8-713A-482B-92F1-3F7D3BCC73E6` is the Bundle GUID of the CoD application
- Checking the different files in the `private/var/mobile/Containers/Data/Application/3690AAA8-713A-482B-92F1-3F7D3BCC73E6/` folder we will stumble uppon the following picture

```
/private/var/mobile/Containers/Data/Application/3690AAA8-713A-482B-92F1-3F7D3BCC73E6/Documents/screenshot.jpg
```

![Call of Duty Rookie IV](media/screenshot.jpg)

- `PlanterPapp` beat `19.9%` players in `Ranked`.

Flag: `19.9`