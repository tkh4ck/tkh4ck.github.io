# CyberQuest 2025 - Where in the world is Tony California 2

## Description

### Where in the world is Tony California 2

Last time you managed to find the hiding place of the notorious Tony California. But before we could capture him he made a daring escape. Now the Agency needs your help once again to help us find where he is hiding.

**Flag format**: `CQ25{flag}` where `flag` is the country-city-hotelname (hotel name is full lower case and no spaces)

*By incarrnati0n*

## Metadata

- Filename: [`conversation.txt`](files/conversation.txt)
- Tags: `osint`, `google maps`

## Solution

We were given with the following conversation:

```
[T.C.]
Hey, they almost got me in Germany. Pheew that was close, but we definitely have to be more careful next time.
[???]
Maybe they somehow got hold of our last conversation and figured it out.
[T.C.]
Could be. Anyway just got to the place.
[???]
How many hours this time?
[T.C.]
Around 15 give or take but atleast no trains this time.
[???]
Seems like those trains got on your nerves.
[T.C.]
Haha funny...  At least it's better than in Wilhelmshaven
[???]
Oh really, maybe we have to move the drop offs to mostly outside of europe then. Could be cost effective haha.
[T.C.]
Yeah, only problem is that I can't speak this language, even though I know some mandarin it's useless here.
[???]
Yeah they have really weird symbols, but atleast the soup is good/cheap so take what you get.
[T.C.]
Shut up.... but true, I stand out a bit too much with my height plus I preferred the german girls, some of them here seem like they have male-ish faces
[???]
Anywaaay, the meeting place is enclosed by the river, the palace, a medical school and a museum you can't really miss it. Are you in the area? Where are you staying?
[T.C.]
Yeah, I think I'm quite close to it. Should be walking distance, I directly next to the royal pavillon.
[???]
Great, it's settled then. Maybe if you want to be a bit more out of sight go to the nearest metro station and circle around. The less time you spend above ground it's less likely for people to spot you.
[T.C.]
Will do, meet you there!
```

After some time spend on Google Maps I've found the solution:
- Thailand
- Bangkok
- Here Hostel Bangkok

<https://www.google.com/maps/search/hotel/@13.7557246,100.5040821,19.52z/data=!4m4!2m3!5m1!3e3!6e3?entry=ttu&g_ep=EgoyMDI1MDkyNC4wIKXMDSoASAFQAw%3D%3D>

Flag: `CQ25{Thailand-Bangkok-herehostelbangkok}`