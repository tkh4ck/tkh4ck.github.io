# HCSC 2024 - Cool o' red Met Alls

## Description

A flag formátuma: `HCSC24{...}`


> Hint 1 (cost 0): Admin bácsi közli velem<br>
> megy ez, mint a veszedelem...<br>
> Ami nem megy, nehéz vagyon<br>
> súgjunk nekik, kicsit-nagyot...<br>
> –––––––––––––––––––––––––––––––––––––––––<br>
> Segítségül egy kis hint:<br>
> A zip fájlban van több kincs!<br>
> Hogy hogyan nyílik, képen rejlik:<br>
> Az arányok is ezt segítik!<br>
> –––––––––––––––––––––––––––––––––––––––––

## Metadata

- Tags: `zip`, `steghide`, `ratios`
- Points: `400`
- Number of solvers: `1`
- Filename: [`bogyo.jpg`](files/bogyo.jpg), [`fs.jpg`](files/fs.jpg), [`vonalzo.jpg`](files/vonalzo.jpg), [`flag.zip`](files/flag.zip)

## Solution

**I was not able to solve this challenge, the solution is from `bombera`**

If we check the size of the image (and use the hint), we might figure out that it is the `golden ratio` (`968/598 = 1.6187290969899666`)

```
$ exiftool bogyo.jpg
Exif Image Width                : 968
Exif Image Height               : 598
$ exiftool fs.jpg
Image Width                     : 967
Image Height                    : 667
```

The `flag.zip` is an encrypted ZIP file, with the password: `golden_ratio`

There are 4 new files:

```bash
$ zipinfo flag.zip 
Archive:  flag.zip
Zip file size: 1542852 bytes, number of entries: 4
-rw-r--r--  3.0 unx   226072 BX defN 24-Feb-25 11:41 bookcover.jpg
-rw-r--r--  3.0 unx   911508 BX defN 24-Feb-25 17:08 divines.jpg
-rw-r--r--  3.0 unx   355432 BX defN 24-Feb-25 17:16 Number.png
-rw-r--r--  3.0 unx    57781 BX defN 23-Oct-27 13:50 problem.png
```

The last step is a `steghide` extraction with the password `Fibonacci` on `bookcover.jpg`. I have no idea how we get this password (maybe the `Problem.png` with the rabbits).

```
$ steghide extract -sf bookcover.jpg 
Enter passphrase: 
wrote extracted data to "flag.txt".
```

```
$ cat flag.txt 


   HCSC24{
        p H y m S o a 3 b u 4 e 
        q X x O P R v h u g B B 
        G 0 U v A j z B m e 8 R 
        T V 6 Y F B t 9 U c B t 
        J 2 8 r y F n 7 a p w S 
        1 N O e t 5 v g 5 d x 0 
        F G P V X f W S X f K A 
        X b M f c W L c 7 d M o 
        z c n v n L M 3 Y G J L 
        P m i c 8 F K G o d A K 
        1 4 I f o c R 6 v s G F 
        n 2 x D B S 3 d n b A 3 
    }


That's easy... 
```

I have no idea what is the last step...

Flag: `HCSC24{???}`