package com.idemix.kavin;

import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Properties;
import java.util.Set;

import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;
import org.hyperledger.fabric.gateway.Identities;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.gateway.X509Identity;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollmentSerialized;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;

public class RegisterAndEnrollAndStoreUserInWallet {

	static {
		System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
	}

	public static void main(String[] args) throws Exception {
		
		String enrollmentId = "appUser4";
		String caCertPEM = System.getProperty("user.home") + "/Desktop/test/idemix-demo-fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem";

		// Create a CA client for interacting with the CA.
		Properties props = new Properties();
		props.put("pemFile", caCertPEM);
		props.put("allowAllHostNames", "true");
		HFCAClient caClient = HFCAClient.createNewInstance("https://localhost:7054", props);
		CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
		caClient.setCryptoSuite(cryptoSuite);

		// Create a wallet for managing identities
		Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));

		// Check to see if we've already enrolled the user.
		if (wallet.get(enrollmentId) != null) {
			System.out.println("An identity for the user " + enrollmentId  + " already exists in the wallet");
			return;
		}

		X509Identity adminIdentity = (X509Identity)wallet.get("admin");
		if (adminIdentity == null) {
			System.out.println("\"admin\" needs to be enrolled and added to the wallet first");
			return;
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
		RegistrationRequest registrationRequest = new RegistrationRequest(enrollmentId);
		registrationRequest.setAffiliation("org1.department1");
		registrationRequest.setEnrollmentID(enrollmentId);
		String enrollmentSecret = caClient.register(registrationRequest, admin);
		Enrollment enrollment = caClient.enroll(enrollmentId, enrollmentSecret);

        IdemixEnrollmentSerialized idemixEnrollment =  (IdemixEnrollmentSerialized) caClient.idemixEnrollAsString(enrollment, "Org1IdemixMSP");
		System.out.println("\nIdemix Enrollment IPK: " + idemixEnrollment.getIpk());
		System.out.println("\nIdemix enrollment MSP: " + idemixEnrollment.getMspId());



		Identity user = Identities.newX509Identity("Org1MSP", enrollment);
		wallet.put(enrollmentId, user);


        Identity id =  Identities.newIdemixIdentity("Org1IdemixMSP", idemixEnrollment);
		wallet.put(enrollmentId + "Idemix", id);

		System.out.println("Successfully enrolled user " + enrollmentId + " and imported it into the wallet");
	}

}
