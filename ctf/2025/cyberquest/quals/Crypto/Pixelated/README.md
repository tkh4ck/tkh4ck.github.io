# CyberQuest 2025 - Pixelated

## Description

I have two images.

Separate, they’re noise. Together, they whisper how the flag turned into this: `VHFEXT3TS5TKHBZ7UHFD45KAS5BKP3KX`

Extend the flag to match this format: `CQ25{...}`

## Metadata

- Filename: [`image1.png`](files/image1.png), [`image2.png`](files/image2.png)
- Tags: 

## Solution

The description of the challenge suggests that the two images should be merged:

```python
from PIL import Image

# Opening the primary image (used in background)
img1 = Image.open(r"image1.png")

# Opening the secondary image (overlay image)
img2 = Image.open(r"image2.png")

# Pasting img2 image on top of img1 
# starting at coordinates (0, 0)
img1.paste(img2, (0,0), mask = img2)

# Displaying the image
img1.show()
```

![Merged image](media/merged.png)

The resulting image shows that the flag should be `base32` decoded and then `ROT7` decoded:

<https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,-7)From_Base32('A-Z2-7%3D',true)&input=VkhGRVhUM1RTNVRLSEJaN1VIRkQ0NUtBUzVCS1AzS1g&oeol=VT>

Flag: `CQ25{p1x3l_X0R_h1nts_h4lp}`