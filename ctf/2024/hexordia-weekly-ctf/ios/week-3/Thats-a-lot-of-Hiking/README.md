# Hexordia Weekly CTF - iOS - Week 3 - That's a lot of Hiking

> What's the total elevation?

- Points: `15`

## Solution

- The owner of the iPhone went to skiing, we can find this out if we check the pictures taken with the phone (`/private/var/mobile/Media/DCIM/100APPLE`)
- There is a picture ([`IMG_0028.HEIC`](media/IMG_0028.HEIC)) of a "statue" showing the different mountains and their elevations in the area at `/private/var/mobile/Media/DCIM/100APPLE/IMG_0028.HEIC`

![Elevation of the mountains](media/IMG_0028.jpg)

- By adding the elevations together, we can get the flag

```
  10568
+ 12313
+ 13010
+ 11570
+ 12998
+ 10700
-------
  71159
```

- To be honest, this challenge was for from intuitive. I've search all location information on the phone (`Health`, `Apple Pay`, `Location Tracking`, `EXIF information (geolocation)`) without luck.

Flag: `71159`