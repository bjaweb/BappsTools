package com.bja.bapps.tools.security.test;


import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.bja.bapps.tools.security.Utils;
import com.bja.bapps.tools.security.helper.CertGenHelper;

public class CreationCA {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		CertGenHelper caGenHelper = new CertGenHelper("bjaweb - benapps");
		caGenHelper.setEmail("bja@bjaweb.com");
		caGenHelper.setOrganisation("bjaweb");
		caGenHelper.setPays("FR");
		caGenHelper.setVille("Verberie");
		
		CertGenHelper certGenHelper = new CertGenHelper("Bernard_Janvion");
		certGenHelper.setEmail("bjanvion@gmail.com");
		certGenHelper.setOrganisation("bjaweb");
		certGenHelper.setPays("FR");
		certGenHelper.setVille("Verberie");
		
//
		X509V1CertificateGenerator certificateCaGenerator = caGenHelper.certGenV1();
		
		try {
			KeyPair caKeyPair = Utils.generateRSAKeyPair();
			KeyPair keyPair = Utils.generateRSAKeyPair();
			
			X509Certificate caCert= Utils.generateSignedCACertificate(certificateCaGenerator,caKeyPair);
			Utils.writeX509CertificatePem("D:/tmp/cert/bjaweb",caCert );
			Utils.writeObjetFormatPem("D:/tmp/cert/", caKeyPair.getPrivate(), "bjawebPrivKey");
			//			PemWriter pw = new PemWriter()
			
			
			X509V3CertificateGenerator certificateGenerator = certGenHelper.certGenV3(caCert);
			X509Certificate cert = Utils.generateSignedCertificate(certificateGenerator, caCert, caKeyPair.getPrivate(),keyPair);
			Utils.writeX509CertificatePem("D:/tmp/cert/bjanvionCert",cert );
			Utils.writeObjetFormatPem("D:/tmp/cert/", keyPair.getPrivate(), "bjanvionPrivKey");
			
		} catch (Exception e) {
			
			e.printStackTrace();
		}
		
	}

}
