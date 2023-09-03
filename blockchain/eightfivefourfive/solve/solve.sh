# Using foundry tools https://book.getfoundry.sh/

RPC_URL=https://blockchain-eightfivefourfive-92cea86e4a6dfad6-eth.shoes-are-nice.ductf.dev:8545
API_URL=https://blockchain-eightfivefourfive-92cea86e4a6dfad6.shoes-are-nice.ductf.dev
PRIVATE_KEY=$(curl -s ${API_URL}/challenge | jq -r ".player_wallet.private_key")
CONTRACT_ADDRESS=$(curl -s ${API_URL}/challenge | jq -r ".contract_address")

# Check status before solution
is_solved=`cast call $CONTRACT_ADDRESS "isSolved()(bool)" --rpc-url ${RPC_URL}`
echo "Solved Status: $is_solved"

# retrieve the private string
string=`cast call $CONTRACT_ADDRESS "readTheStringHere()(string)" --rpc-url ${RPC_URL}`

# solve the challenge
cast send $CONTRACT_ADDRESS "solve_the_challenge(string)" "I can connect to the blockchain!" --private-key $PRIVATE_KEY --legacy --rpc-url ${RPC_URL}

is_solved=`cast call $CONTRACT_ADDRESS "isSolved()(bool)" --rpc-url ${RPC_URL}`
echo "Solved Status: $is_solved"

curl -s ${API_URL}/challenge/solve | jq  -r ".flag"
