package com.idemix.kavin;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Properties;

import org.hyperledger.fabric.gateway.Identities;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class EnrollAdmin {

	static {
		System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
	}


	public static void main(String[] args) throws EnrollmentException, InvalidArgumentException, CertificateException, IOException, CryptoException, org.hyperledger.fabric.sdk.exception.InvalidArgumentException, ClassNotFoundException, IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException {
		System.out.println("Application is running!");

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

		// Check to see if we've already enrolled the admin user.
		if (wallet.get("admin") != null) {
			System.out.println("An identity for the admin user \"admin\" already exists in the wallet");
			return;
		}

		// Enroll the admin user, and import the new identity into the wallet.
		final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
		enrollmentRequestTLS.addHost("localhost");
		Enrollment enrollment = caClient.enroll("admin", "adminpw", enrollmentRequestTLS);
		// IdemixEnrollmentSerialized idemixEnrollment =  (IdemixEnrollmentSerialized) caClient.idemixEnrollAsString(enrollment, "Org1IdemixMSP");
		// System.out.println("Idemix Enrollment IPK: " + idemixEnrollment.getIpk());
		// System.out.println("Idemix enrollment MSP: " + idemixEnrollment.getMspId());

		Identity user = Identities.newX509Identity("Org1MSP", enrollment);
		wallet.put("admin", user);

		// Identity id =  Identities.newIdemixIdentity("Org1IdemixMSP", idemixEnrollment);
		// wallet.put("admin11", id);

		System.out.println("Successfully enrolled user \"admin\" and imported it into the wallet");

		

	}

}
