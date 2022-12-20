package com.idemix.kavin;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

public class SubmitTxUsingOldGatewayJavaSDK {

	static {
		System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
	}

	public static void main(String[] args) throws Exception {
		// Load a file system based wallet for managing identities.
		Path walletPath = Paths.get("wallet");
		Wallet wallet = Wallets.newFileSystemWallet(walletPath);
		// load a CCP
		Path networkConfigPath = Paths.get("/home/kavin/work/my/opensource/2022/git_repos/gateway-idemix/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/connection-org1.yaml");

		Gateway.Builder builder = Gateway.createBuilder();
		builder.identity(wallet, "appUser4Idemix").networkConfig(networkConfigPath).discovery(true);

		// create a gateway connection
		try (Gateway gateway = builder.connect()) {

			// get the network and contract
			Network network = gateway.getNetwork("mychannel");
			Contract contract = network.getContract("basic");

			byte[] result;

			result = contract.evaluateTransaction("GetAllAssets");
            System.out.println("\n\n\n");
			System.out.println(new String(result));
            System.out.println("\n\n\n");

//			contract.submitTransaction("createCar", "CAR10", "VW", "Polo", "Grey", "Mary");
//
//			result = contract.evaluateTransaction("queryCar", "CAR10");
//            System.out.println("\n\n\n");
//			System.out.println(new String(result));
//            System.out.println("\n\n\n");
//
//
//			contract.submitTransaction("changeCarOwner", "CAR10", "Archie");
//
//			result = contract.evaluateTransaction("queryCar", "CAR10");
//            System.out.println("\n\n\n");
//			System.out.println(new String(result));
//            System.out.println("\n\n\n");

		}
	}

}