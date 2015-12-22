package com.bja.bapps.tools.security;

import java.security.cert.X509Certificate;

public class VerifCertifParCa {

	/**
	 * Ceci est un petit utilitaire de test pour verifier qu'un certificat a bien été signé par son CA 
	 * @param args
	 */
	public static void main(String[] args) {
	
		X509Certificate ca = Utils.readCertificate("c:/test2/cacert.cer");
		X509Certificate cert = Utils.readCertificate("c:/test2/06BA.pem");
		
		try {
			isSignedByCa(cert, ca);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
		
	
		public static boolean isSignedByCa(X509Certificate cert,X509Certificate ca) throws Exception{
			
			try{
				System.out.println(cert.getPublicKey());
				
				cert.verify(ca.getPublicKey());
				System.out.println("-->valide /");
				return true;

			}catch (Exception e) 
			{					
				e.printStackTrace();
				throw new Exception("certificat mal signé par autorité");
			}
			
			
		}

	

}
