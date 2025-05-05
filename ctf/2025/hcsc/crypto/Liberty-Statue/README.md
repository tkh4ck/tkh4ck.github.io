# HCSC 2025 - Liberty Statue

## Description

The Liberty Statue itself stands 14 metres tall, and with its pedestal, it reaches a total height of 40 metres above the 235-metre-high Gellért Hill. Situated near the southeastern bastion of the Citadella, the monument is prominently visible from various points across the city. As part of the Citadella's ongoing renovation since 2021, the statue underwent a comprehensive reconstruction between 2023 and 2024.

Flag format: `HCSC{...}`

## Metadata

- Filename: [`liberty_statue.jpg](files/liberty_statue.jpg)
- Tags: `not-crypto`, `stego`, `strings`, `exiftool`, `steghide`
- Points: 150
- Number of solvers: 134

## Solution

We have an image, let's run `exiftool`:

```bash
$ exiftool liberty_statue.jpg 
ExifTool Version Number         : 13.10
File Name                       : liberty_statue.jpg
Directory                       : .
File Size                       : 173 kB
File Modification Date/Time     : 2025:04:24 20:50:38+00:00
File Access Date/Time           : 2025:04:29 15:03:11+00:00
File Inode Change Date/Time     : 2025:04:24 20:51:14+00:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
XMP Toolkit                     : Image::ExifTool 13.04
Secret                          : TDFiNHJ0eV8xODg2IQ==
Image Width                     : 749
Image Height                    : 524
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 749x524
Megapixels                      : 0.392
```

There is a `Secret` metadata with the value `TDFiNHJ0eV8xODg2IQ==`.

Base64 decoding this gives: `L1b4rty_1886!`

Now we can guess and use `steghide` with this password.

```bash
$ steghide extract -sf liberty_statue.jpg
Enter passphrase:
wrote extracted data to "flag.txt".
$ cat flag.txt
HCSC{Th3_d@y_0f_lib4rty}
```

The flag is: `HCSC{Th3_d@y_0f_lib4rty}`