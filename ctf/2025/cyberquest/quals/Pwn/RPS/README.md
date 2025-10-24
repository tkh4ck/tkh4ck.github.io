# CyberQuest 2025 - RPS

## Description

### RPS

Ever played a game of rock, paper, scissors where couldn't read you opponent? What if he/she always chooses based on a set pattern, you could always know how to beat your opponent. It would be pretty useful in my opinion.

#### Creators comments:

> * No brute forcing is required
> * Use the given file
> * VPN connection is required

 **Flag format**: `CQ25{flag}`

*By incarrnati0n*

`cq25-challenge0[1-9]-a.cq.honeylab:41111`

## Metadata

- Filename: [`game_redacted.cpp`](files/game_redacted.cpp)
- Tags: `brute-force`, `rand`, `srand`, `time(0)`

## Solution

In this challenge we have to win against the server in rock-paper-scissors 5 times in a row.

The `srand` function is seeded with `time(0)`, which should make the `rand` function predicable and it might be possible the predict the hands of the server (even with `mod 3`), however, there are some problems, which make this impossible:
- It is unknown when the services are started (or restarted) on the server
- All the players are using the same shared instances

Because of this, as far as I know all solutions from the players were based on brute-forcing.

I also tried brute-forcing and after a short time I was lucky:

```
nc 10.10.100.111 41111
Current number of wins: 0
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: paper
You lose!
Current number of wins: 0
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: paper
You lose!
Current number of wins: 0
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 1
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 2
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: paper
You lose!
Current number of wins: 0
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 1
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 2
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: rock
It's a draw!
Current number of wins: 0
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: rock
It's a draw!
Current number of wins: 0
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: paper
You lose!
Current number of wins: 0
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 1
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 2
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 3
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Current number of wins: 4
Fancy a game of rock, paper, scissors?
Press 1 to play a game
Press 2 to exit the game
1
Enter your choice (1-3)
1:Rock, 2:Paper, 3:Scissor
1
Your hand: rock
Computer's hand: scissor
Congrats you win!
Congrats! Here is your flag: CQ25{Gr34t_gU3sS1nG}
```

Flag: `CQ25{Gr34t_gU3sS1nG}`