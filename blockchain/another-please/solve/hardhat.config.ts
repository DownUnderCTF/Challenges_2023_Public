import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.19",
  defaultNetwork: "ductf",
  networks: {
    ductf: {
      url: "http://localhost:8545",
    },
  },
};

export default config;
