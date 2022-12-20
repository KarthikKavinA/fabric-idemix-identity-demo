package com.idemix.kavin;



/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.client.CommitException;
import org.hyperledger.fabric.client.CommitStatusException;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.EndorseException;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.GatewayException;
import org.hyperledger.fabric.client.SubmitException;
import org.hyperledger.fabric.client.identity.IdemixerIdentity;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;
import org.hyperledger.fabric.client.identity.exception.CryptoException;
import org.hyperledger.fabric.client.identity.exception.InvalidArgumentException;
import org.hyperledger.fabric.client.identity.idemix.IdemixCredential;
import org.hyperledger.fabric.client.identity.idemix.IdemixIdentity;
import org.hyperledger.fabric.client.identity.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.client.identity.idemix.IdemixPseudonym;
import org.hyperledger.fabric.client.identity.idemix.IdemixSignature;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollmentSerialized;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;

import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static java.nio.charset.StandardCharsets.UTF_8;

// Register and Enroll and Store Idemix Identity in a Wallet
// Then using, Idemix Signer and Idemix Identity, we are invoking and querying the chaincode.
// Prerequisite Setup: Test Network(2.4.3 or greater) with "mychannel" and "basic" chaincode (golang only supported) deployed in it.
public final class SubmitTxUsingIdemixIdentity {
	private static final String MSP_ID = System.getenv().getOrDefault("MSP_ID", "Org1MSP");
	private static final String CHANNEL_NAME = System.getenv().getOrDefault("CHANNEL_NAME", "mychannel");
	private static final String CHAINCODE_NAME = System.getenv().getOrDefault("CHAINCODE_NAME", "basic");

	// Path to crypto materials.
	private static final Path CRYPTO_PATH = Paths.get("/home/kavin/work/my/opensource/2022/git_repos/gateway-idemix/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com");
	// Path to user certificate.
	private static final Path CERT_PATH = CRYPTO_PATH.resolve(Paths.get("users/User1@org1.example.com/msp/signcerts/cert.pem"));
	// Path to user private key directory.
	private static final Path KEY_DIR_PATH = CRYPTO_PATH.resolve(Paths.get("users/User1@org1.example.com/msp/keystore"));
	// Path to peer tls certificate.
	private static final Path TLS_CERT_PATH = CRYPTO_PATH.resolve(Paths.get("peers/peer0.org1.example.com/tls/ca.crt"));

	// Gateway peer end point.
	private static final String PEER_ENDPOINT = "localhost:7051";
	private static final String OVERRIDE_AUTH = "peer0.org1.example.com";

	private final Contract contract;
	private final String assetId = "asset" + Instant.now().toEpochMilli() + "Idemix";
	private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
	
    // discloseFlags will be passed to the idemix signing and verification
    // routines.
    // It informs idemix to disclose both attributes (OU and Role) when signing.
	private static final boolean[] disclosedFlags = new boolean[]{true, true, false, false};

    // empty message to sign in the validate identity proof
    private static final byte[] msgEmpty = {};
        
    // hashing implementation used to generate digests of messages sent to the Fabric network.
    private static final Function<byte[], byte[]> msgSigning = message -> message;

    // the revocation handle is always the third attribute
    private static final int rhIndex = 3;
   
    

	public static void main(final String[] args) throws Exception {
		// The gRPC client connection should be shared by all Gateway connections to
		// this endpoint.
		var channel = newGrpcConnection();
		
		IdemixEnrollmentSerialized idemixEnrollmentSerialized = null;
		try {
			
			idemixEnrollmentSerialized = enrollIdemixIdentity("appUser" + Instant.now().toEpochMilli());

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// user's secret
		String sk = idemixEnrollmentSerialized.getSk();
		byte[] skBytes = Base64.getDecoder().decode(sk.getBytes());
		BIG skFinal = BIG.fromBytes(skBytes);

		// public key of the Idemix CA (issuer)
		byte[] ipkBytes = Base64.getDecoder().decode(idemixEnrollmentSerialized.getIpk().getBytes());
		Idemix.IssuerPublicKey ipkProto = Idemix.IssuerPublicKey.parseFrom(ipkBytes);
		IdemixIssuerPublicKey ipkFinal = new IdemixIssuerPublicKey(ipkProto);
		
		// idemix pseudonym (represents Idemix identity)
		IdemixPseudonym idemixPseudonymFinal = new IdemixPseudonym(skFinal, ipkFinal);
		
		var builder = Gateway.newInstance().identity(newIdemixIdentity(idemixEnrollmentSerialized, idemixPseudonymFinal)).signer(newIdemixSigner(skFinal, idemixPseudonymFinal, ipkFinal)).connection(channel)
				// Default timeouts for different gRPC calls
				
				.evaluateOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
				.endorseOptions(options -> options.withDeadlineAfter(15, TimeUnit.SECONDS))
				.submitOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
				.commitStatusOptions(options -> options.withDeadlineAfter(1, TimeUnit.MINUTES))
				.hash(msgSigning);

		try (var gateway = builder.connect()) {
			new SubmitTxUsingIdemixIdentity(gateway).run();
		} finally {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}

	private static ManagedChannel newGrpcConnection() throws IOException, CertificateException {
		var tlsCertReader = Files.newBufferedReader(TLS_CERT_PATH);
		var tlsCert = Identities.readX509Certificate(tlsCertReader);

		return NettyChannelBuilder.forTarget(PEER_ENDPOINT)
				.sslContext(GrpcSslContexts.forClient().trustManager(tlsCert).build()).overrideAuthority(OVERRIDE_AUTH)
				.build();
	}

	private static Identity newIdentity() throws IOException, CertificateException {
		var certReader = Files.newBufferedReader(CERT_PATH);
		var certificate = Identities.readX509Certificate(certReader);

		return new X509Identity(MSP_ID, certificate);
	}

	private static Signer newSigner() throws IOException, InvalidKeyException {
		var keyReader = Files.newBufferedReader(getPrivateKeyPath());
		var privateKey = Identities.readPrivateKey(keyReader);

		return Signers.newPrivateKeySigner(privateKey);
	}
	
	private static Signer newIdemixSigner(BIG sk, IdemixPseudonym idemixPseu, IdemixIssuerPublicKey ipk) {
		return Signers.newIdemixPrivateKeySigner(sk, idemixPseu, ipk);
	}
	
	private static Identity newIdemixIdentity(IdemixEnrollmentSerialized idemixEnrollmentSerialized, IdemixPseudonym idemixPseFinal) throws InvalidArgumentException, CryptoException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		String mspId = idemixEnrollmentSerialized.getMspId();
		String ouString = idemixEnrollmentSerialized.getOu();
		int roleMask = Integer.parseInt(idemixEnrollmentSerialized.getRoleMask());
		
		// idemix credential
		String credstr = idemixEnrollmentSerialized.getCred();
		byte[] credBytes = Base64.getDecoder().decode(credstr.getBytes(UTF_8));
		Idemix.Credential credProto = Idemix.Credential.parseFrom(credBytes);
		IdemixCredential credFinal = new IdemixCredential(credProto);
		
		// user's secret
		String sk = idemixEnrollmentSerialized.getSk();
		byte[] skBytes = Base64.getDecoder().decode(sk.getBytes());
		BIG skFinal = BIG.fromBytes(skBytes);
		
		// credental revocation information
		String criStr = idemixEnrollmentSerialized.getCri();
		byte[] criBytes = Base64.getDecoder().decode(criStr.getBytes(UTF_8));
		Idemix.CredentialRevocationInformation criFinal = Idemix.CredentialRevocationInformation.parseFrom(criBytes);

		// public key of the Idemix CA (issuer)
		byte[] ipkBytes = Base64.getDecoder().decode(idemixEnrollmentSerialized.getIpk().getBytes());
		Idemix.IssuerPublicKey ipkProto = Idemix.IssuerPublicKey.parseFrom(ipkBytes);
		IdemixIssuerPublicKey ipkFinal = new IdemixIssuerPublicKey(ipkProto);
		
		// attribute checks
        // 4 attributes are expected:
        // - organization unit (disclosed)
        // - role: admin or member (disclosed)
        // - enrollment id (hidden, for future auditing feature and authorization with CA)
        // - revocation handle (hidden, for future revocation support)
		BIG[] attributes = new BIG[4];
        attributes[0] = BIG.fromBytes(credFinal.getAttrs()[0]);
        attributes[1] = BIG.fromBytes(credFinal.getAttrs()[1]);
        attributes[2] = BIG.fromBytes(credFinal.getAttrs()[2]);
        attributes[3] = BIG.fromBytes(credFinal.getAttrs()[3]);
        
        // the issuer's long term revocation public key
        String revocationKeyStr = idemixEnrollmentSerialized.getRevocationPk();
        String pem = new String(Base64.getDecoder().decode(revocationKeyStr));
        PemReader pemReader = new PemReader(new StringReader(pem));
        byte[] der = pemReader.readPemObject().getContent();
        PublicKey revocationKeyFinal = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
		
		IdemixSignature idemixSignature = new IdemixSignature(credFinal, skFinal, idemixPseFinal, ipkFinal, disclosedFlags, msgEmpty, rhIndex, criFinal);
		System.out.println("\nVerifying the Idemix Signature...");
		if (!idemixSignature.verify(disclosedFlags, ipkFinal, msgEmpty, attributes, rhIndex, revocationKeyFinal, (int) criFinal.getEpoch())) {
			System.out.println("Generated proof of identity is NOT VALID");
		} else {
			System.out.println("Generated proof of identity is VALID");
		}
		IdemixIdentity idemixIdentity =  new IdemixIdentity(mspId, ipkFinal, idemixPseFinal.getNym(), ouString, roleMask, idemixSignature);
		
		return new IdemixerIdentity("Org1IdemixMSP", idemixIdentity);
	}

	private static Path getPrivateKeyPath() throws IOException {
		try (var keyFiles = Files.list(KEY_DIR_PATH)) {
			return keyFiles.findFirst().orElseThrow();
		}
	}

	public SubmitTxUsingIdemixIdentity(final Gateway gateway) {
		// Get a network instance representing the channel where the smart contract is
		// deployed.
		var network = gateway.getNetwork(CHANNEL_NAME);

		// Get the smart contract from the network.
		contract = network.getContract(CHAINCODE_NAME);
	}

	public void run() throws GatewayException, CommitException {
		// Initialize a set of asset data on the ledger using the chaincode 'InitLedger' function.
//		initLedger();

		// Return all the current assets on the ledger.
//		getAllAssets();

		// Create a new asset on the ledger.
		createAsset();
		
		// Return all the current assets on the ledger.
		getAllAssets();

		// Update an existing asset asynchronously.
//		transferAssetAsync();

		// Get the asset details by assetID.
//		readAssetById();

		// Update an asset which does not exist.
//		updateNonExistentAsset();
	}
	
	
	/**
	 * Enroll Idemix Identity.
	 * @throws MalformedURLException 
	 */
	public static IdemixEnrollmentSerialized enrollIdemixIdentity(String enrollmentID) throws Exception {

		// Enrolling an Admin Identity
		// Create a CA client for interacting with the CA.
		Properties props = new Properties();
		props.put("pemFile",
				"/home/kavin/work/my/opensource/2022/git_repos/gateway-idemix/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem");
		props.put("allowAllHostNames", "true");
		HFCAClient caClient = HFCAClient.createNewInstance("https://localhost:7054", props);
		CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
		caClient.setCryptoSuite(cryptoSuite);

		// Create a wallet for managing identities
		Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));

		// Check to see if we've already enrolled the admin user.
		if (wallet.get("admin") != null) {
			System.out.println("An identity for the admin user \"admin\" already exists in the wallet");
		} else {			
			// Enroll the admin user, and import the new identity into the wallet.
			final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
			enrollmentRequestTLS.addHost("localhost");
			Enrollment enrollment = caClient.enroll("admin", "adminpw", enrollmentRequestTLS);
			org.hyperledger.fabric.gateway.Identity user = org.hyperledger.fabric.gateway.Identities.newX509Identity("Org1MSP", enrollment);
			wallet.put("admin", user);
			System.out.println("Successfully enrolled user \"admin\" and imported it into the wallet");			
		}		


		// Register a New User with CA
		// Check to see if we've already enrolled the user.
		if (wallet.get(enrollmentID) != null) {
			System.out.printf("\nAn identity for the user \"%s\" already exists in the wallet", enrollmentID);
			return null;
		}

		org.hyperledger.fabric.gateway.X509Identity adminIdentity = (org.hyperledger.fabric.gateway.X509Identity)wallet.get("admin");
		if (adminIdentity == null) {
			System.out.println("\"admin\" needs to be enrolled and added to the wallet first");
			return null;
		}
		User admin = new User() {

			@Override
			public String getName() {
				return "admin";
			}

			@Override
			public Set<String> getRoles() {
				return null;
			}

			@Override
			public String getAccount() {
				return null;
			}

			@Override
			public String getAffiliation() {
				return "org1.department1";
			}

			@Override
			public Enrollment getEnrollment() {
				return new Enrollment() {

					@Override
					public PrivateKey getKey() {
						return adminIdentity.getPrivateKey();
					}

					@Override
					public String getCert() {
						return Identities.toPemString(adminIdentity.getCertificate());
					}
				};
			}

			@Override
			public String getMspId() {
				return "Org1MSP";
			}

		};

		// Register the user, enroll the user, and import the new identity into the wallet.
		RegistrationRequest registrationRequest = new RegistrationRequest(enrollmentID);
		registrationRequest.setAffiliation("org1.department1");
		registrationRequest.setEnrollmentID(enrollmentID);
		registrationRequest.setType("admin");
		
		final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
		enrollmentRequestTLS.addHost("localhost");
		
		String enrollmentSecret = caClient.register(registrationRequest, admin);
		Enrollment enrollment1 = caClient.enroll(enrollmentID, enrollmentSecret, enrollmentRequestTLS);

		IdemixEnrollmentSerialized idemixEnrollment = (IdemixEnrollmentSerialized) caClient.idemixEnrollAsString(enrollment1, "Org1IdemixMSP");	

		org.hyperledger.fabric.gateway.Identity user1 = org.hyperledger.fabric.gateway.Identities.newX509Identity("Org1MSP", enrollment1);
		//wallet.put(enrollmentID, user1);
		org.hyperledger.fabric.gateway.Identity idemixUserID = org.hyperledger.fabric.gateway.Identities.newIdemixIdentity("Org1IdemixMSP", idemixEnrollment);
		wallet.put(enrollmentID, idemixUserID);
		System.out.printf("\nSuccessfully enrolled user \"%s\" and imported it into the wallet", enrollmentID);
		

		return idemixEnrollment;
	}
	
	
	
	/**
	 * This type of transaction would typically only be run once by an application
	 * the first time it was started after its initial deployment. A new version of
	 * the chaincode deployed later would likely not need to run an "init" function.
	 */
	private void initLedger() throws EndorseException, SubmitException, CommitStatusException, CommitException {
		System.out.println("\n--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger");

		contract.submitTransaction("InitLedger");

		System.out.println("*** Transaction committed successfully");
	}

	/**
	 * Evaluate a transaction to query ledger state.
	 */
	private void getAllAssets() throws GatewayException {
		System.out.println("\n--> Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger");

		var result = contract.evaluateTransaction("GetAllAssets");
		
		System.out.println("*** Result: " + prettyJson(result));
	}

	private String prettyJson(final byte[] json) {
		return prettyJson(new String(json, StandardCharsets.UTF_8));
	}

	private String prettyJson(final String json) {
		var parsedJson = JsonParser.parseString(json);
		return gson.toJson(parsedJson);
	}

	/**
	 * Submit a transaction synchronously, blocking until it has been committed to
	 * the ledger.
	 */
	private void createAsset() throws EndorseException, SubmitException, CommitStatusException, CommitException {
		System.out.println("\n--> Submit Transaction: CreateAsset, creates new asset with ID, Color, Size, Owner and AppraisedValue arguments");

		contract.submitTransaction("CreateAsset", assetId, "yellow", "5", "Tom", "1300");

		System.out.println("*** Transaction committed successfully");
	}

	/**
	 * Submit transaction asynchronously, allowing the application to process the
	 * smart contract response (e.g. update a UI) while waiting for the commit
	 * notification.
	 */
	private void transferAssetAsync() throws EndorseException, SubmitException, CommitStatusException {
		System.out.println("\n--> Async Submit Transaction: TransferAsset, updates existing asset owner");

		var commit = contract.newProposal("TransferAsset")
				.addArguments(assetId, "Saptha")
				.build()
				.endorse()
				.submitAsync();

		var result = commit.getResult();
		var oldOwner = new String(result, StandardCharsets.UTF_8);

		System.out.println("*** Successfully submitted transaction to transfer ownership from " + oldOwner + " to Saptha");
		System.out.println("*** Waiting for transaction commit");

		var status = commit.getStatus();
		if (!status.isSuccessful()) {
			throw new RuntimeException("Transaction " + status.getTransactionId() +
					" failed to commit with status code ");
		}
		
		System.out.println("*** Transaction committed successfully");
	}

	private void readAssetById() throws GatewayException {
		System.out.println("\n--> Evaluate Transaction: ReadAsset, function returns asset attributes");

		var evaluateResult = contract.evaluateTransaction("ReadAsset", assetId);
		
		System.out.println("*** Result:" + prettyJson(evaluateResult));
	}

	/**
	 * submitTransaction() will throw an error containing details of any error
	 * responses from the smart contract.
	 */
	private void updateNonExistentAsset() {
		try {
			System.out.println("\n--> Submit Transaction: UpdateAsset asset70, asset70 does not exist and should return an error");
			
			contract.submitTransaction("UpdateAsset", "asset70", "blue", "5", "Tomoko", "300");
			
			System.out.println("******** FAILED to return an error");
		} catch (EndorseException | SubmitException | CommitStatusException e) {
			System.out.println("*** Successfully caught the error: ");
			e.printStackTrace(System.out);
			System.out.println("Transaction ID: " + e.getTransactionId());

//			var details = e.getDetails();
//			if (!details.isEmpty()) {
//				System.out.println("Error Details:");
//				for (var detail : details) {
//					System.out.println("- address: " + detail.getAddress() + ", mspId: " + detail.getMspId()
//							+ ", message: " + detail.getMessage());
//				}
//			}
		} catch (CommitException e) {
			System.out.println("*** Successfully caught the error: " + e);
			e.printStackTrace(System.out);
			System.out.println("Transaction ID: " + e.getTransactionId());
//			System.out.println("Status code: " + e.getCode());
		}
	}
}

