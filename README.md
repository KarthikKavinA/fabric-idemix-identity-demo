# fabric-idemix-identity-demo
Demo Application for using Identity Mixer Identity in Fabric with Fabric Gateway Client API for Java and Fabric Gateway SDK for Java

## Getting Started
**Open a Terminal & Set Fabric Path. This is where our modified fabric-samples for Idemix Identity will reside.**
```bash
FABRIC_PATH=~/Desktop/test && cd $FABRIC_PATH
```

**Clone the repository**
```bash
git clone https://github.com/KarthikKavinA/idemix-demo-fabric-samples.git
```

**Navigate to test-network folder**
```bash
cd idemix-demo-fabric-samples/test-network
```

**Bring down the network to remove any crypto materials if any exists already**
```bash
./network.sh down
```

**Bring Up the network with Fabric CA**
```bash
./network.sh up -ca
```

**Create a channel named "mychannel"**
```bash
./network.sh createChannel -c mychannel
```

**Deploy the Go Chaincode to "mychannel"**

**Note: (Only Golang Chaincodes will have support for Idemix, Other chaincodes won't work with Idemix). For More Details, [click here](https://hyperledger-fabric.readthedocs.io/en/latest/idemix.html).**
```bash
./network.sh deployCC -c mychannel -ccn basic -ccl go -ccp ../asset-transfer-basic/chaincode-go
```

**Interacting with the network - Invocation and Query**

**a) Set Environmental Variables - (Org1MSP)**
```bash
export FABRIC_CFG_PATH=${PWD}/./config
. scripts/envVar.sh
setGlobals 1
```

**b) Invoking the Chaincode - (Note: x509 MSP is set in above env variables)**
```bash
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n basic --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"InitLedger","Args":[]}'
```

**c) Query the Chaincode**
```bash
peer chaincode query -C mychannel -n basic -c '{"Args":["GetAllAssets"]}' | jq .
```


## Submit Transaction using Idemix Identity from CLI
**a) Generating an Idemix Credential for an User**
```bash
FABRIC_PATH=~/Desktop/test
cd $FABRIC_PATH/idemix-demo-fabric-samples/test-network/organizations/peerOrganizations/org1.example.com
idemixgen signerconfig --ca-input=idemixmsp --admin --enrollmentId=appUser --org-unit=org1
```

**b) Setting Environmental Variables for Idemix Identity**
```bash
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE=$FABRIC_PATH/idemix-demo-fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPTYPE=idemix
export CORE_PEER_LOCALMSPID=Org1IdemixMSP
export CORE_PEER_MSPCONFIGPATH=$FABRIC_PATH/idemix-demo-fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/idemix-config
```

**c) Invoking the Chaincode - (Note: idemix MSP is set in above env variables)**
```bash
cd $FABRIC_PATH/idemix-demo-fabric-samples/test-network
export FABRIC_CFG_PATH=$PWD/./config
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n basic --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"TransferAsset","Args":["asset6","Kavin"]}'
```

**d) Query the Chaicode using Idemix Identity**
```bash
peer chaincode query -C mychannel -n basic -c '{"Args":["GetAllAssets"]}' | jq .
```



