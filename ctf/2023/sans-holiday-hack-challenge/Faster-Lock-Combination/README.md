# SANS Holiday Hack Challenge 2023 - Faster Lock Combination

## Description

> Over on Steampunk Island, Bow Ninecandle is having trouble opening a padlock. Do some research and see if you can help open it!

> **Bow Ninecandle (Brass Bouy Port)**: 
*Hey there! I'm Bow Ninecandle, and I've got a bit of a... 'pressing' situation. You see, I need to get into the lavatory, but here's the twist: it's secured with a combination padlock. Talk about bad timing, right? I could really use your help to figure this out before things get... well, urgent. I'm sure there are some clever [tricks and tips floating around the web](https://www.youtube.com/watch?v=27rE5ZvWLU0) that can help us crack this code without too much of a flush... I mean fuss. Remember, we're aiming for quick and easy solutions here - nothing too complex. Once we've gathered a few possible combinations, let's team up and try them out. I'm crossing my legs - I mean fingers - hoping we can unlock this door soon. After all, everyone knows that the key to holiday happiness is an accessible lavatory! Let's dive into this challenge and hopefully, we won't have to 'hold it' for too long! Ready to help me out?*

### Metadata

- Difficulty: 2/5
- Tags: `lock picking`

## Solution

### Video

<iframe width="1280" height="720" src="https://youtu.be/LtHHYrNxOEw?t=775" title="SANS Holiday Hack Challenge 2023 - Faster Lock Combinations" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### Write-up

If we watch the suggested video, we can get an idea on how to solve the challenge:

[HelpfulLockPicker - [198] Close Up On How To Decode A Dial Combination Lock In 8 Attempts Or Less](https://www.youtube.com/watch?v=27rE5ZvWLU0)

We need three sets of numbers to calculate the combination. The first one is the `STICKY` number, the other two are the `GUESS` numbers.

**Step 1**

First, we want to get the `STICKY` number.

We need to get a bit pull pressure / tension on the shackle and turn the dial counterclockwise. We want to find the number where we consistently get stuck / stop.

In my case the `STICKY` number was `25`.

**Step 2**

Second, we want to find the 2 `GUESS` numbers, they are between 0 and 11.

We have to put heavy tension on the shackle and start turning from 0 clockwise.

The numbers we want to find will sit between two half numbers.

In my case the `GUESS1` was `7` and the `GUESS2` was `8`.

**Step 3/a**

The first digit of the combination is `STICKY + 5 = 25 + 5 = 30`

**Step 3/b**

To find the third digit we have to get the modulo 4 of the first digit number (`REMAINDER`).

30 / 4 = 0
30 % 4 = 2 (`REMAINDER`)

Now, we add 10 to the guess numbers 4 times.

```
7, 17, 27, 37
8, 18, 28, 38
```

Find the one which have the same reminder as the first digit divided by 4.

These are: `18` and `38`.

We refine the third digit of combination from the two found possibilities.

We stop on each number and put heavy tension on the shackle, the number that feels looser, will be the last number.

In my case this was `18`.

**Step 3/c**

To find the second digit we add 2 to the `REMAINDER` and the 4-times 8 to it. Then add 4 to all of the calculate five numbers (remember `40` is `0`, `41` is `1` etc.)

4, 12, 20, 28, 36
8, 16, 24, 32, 0

The second and the third digit must be more than 2 digits away, so the second number in my case can be: `0`, `4`, `8`, `12`, `24`, `28`, `32`, `36`

**Step 4**

Testing out the numbers
- Turn counterclockwise stop at the first digit
- Turn clockwise, pass the second digit once and the stop at it
- Turn counterclockwise and stop at the third digit

I was lucky, as the lock opened on my first try: `30`, `0`, `18`

> **Bow Ninecandle (Brass Bouy Port)**: 
*Oh, thank heavens! You're a lifesaver! With your knack for cracking codes, we've just turned a potential 'loo catastrophe' into a holiday triumph!*