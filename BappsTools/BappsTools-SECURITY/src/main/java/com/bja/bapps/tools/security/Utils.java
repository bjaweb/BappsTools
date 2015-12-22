package com.bja.bapps.tools.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509StreamParser;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import com.bja.bapps.tools.core.utils.dataType.DateUtils;

//import cocom.bja.bapps.toolse.utils.dataType.DateUtils;

public class Utils {

	static{
		Security.addProvider(new BouncyCastleProvider());
	}

	public static KeyPair generateRSAKeyPair() throws SecurityException {
		KeyPairGenerator kpGen=null;
		try {
			kpGen = KeyPairGenerator.getInstance("RSA", "BC");
			kpGen.initialize(1024, new SecureRandom());
			
		
		
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
			throw new SecurityException(e);			
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new SecurityException(e);
		}

		return kpGen.generateKeyPair();


	}

	public static RSAPrivateKey loadClientKey(String keyFile, char[] keyPassword) throws IOException {
		RSAPrivateKey privateKey = null;
		FileReader fileReader = new FileReader(keyFile);

		PEMReader r = new PEMReader(fileReader, new DefaultPasswordFinder(keyPassword));

		try {
			KeyPair kp = (KeyPair) r.readObject();
			privateKey = (RSAPrivateKey) kp.getPrivate();
			return privateKey;
		} catch (IOException exc) {
			throw new IOException("Erreur, la clé privée est incorrecte"+ exc);
		} finally {
			r.close();
			fileReader.close();
		}
	}


	public static X509Certificate readCertificate(String path){
		X509Certificate cert = null;
		try{

			X509StreamParser parser = X509StreamParser.getInstance("Certificate", "BC");

			FileInputStream stream = null;
			File certifFile = new File(path);
			stream =  new FileInputStream(certifFile);

			parser.init(stream);
			cert = (X509Certificate) parser.read();
			stream.close();

		}catch (Exception e) {
			e.printStackTrace();
		}

		return cert;


	}

	public static X509Certificate generateSignedCertificate(X509V3CertificateGenerator certGen, X509Certificate caCert, PrivateKey caPrivateKey,KeyPair keyPair) throws Exception{
		
		X509Certificate cert = null;
		// GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
		// = generateRSAKeyPair();    

		certGen.setPublicKey(keyPair.getPublic());     
		
		certGen.setSignatureAlgorithm("MD5WithRSAEncryption");
		
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));

		certGen.addExtension(X509Extensions.SubjectKeyIdentifier,false, new SubjectKeyIdentifierStructure(keyPair.getPublic()));

		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

		//			certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

		
		
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("MD5WithRSAEncryption");


		cert = certGen.generate(caPrivateKey);
		System.out.println("\ncertificat"+cert);
		
		
		System.out.println("CERTIFICATE TO_STRING");     
		
		System.out.println();     
		System.out.println(cert);     
		System.out.println();      
		System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");     
		System.out.println();     
		PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));     
		pemWriter.writeObject(cert);     
		pemWriter.flush();     
		System.out.println();      
		System.out.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");     
		System.out.println();     
		pemWriter.writeObject(keyPair.getPrivate());     
		pemWriter.flush();     
		System.out.println(); 
		
		return cert;
	}


	
	public static X509Certificate generateSignedCACertificate(X509V1CertificateGenerator certGen,KeyPair keyPair) throws Exception{
		

		certGen.setPublicKey(keyPair.getPublic());     
		
		certGen.setSignatureAlgorithm("MD5WithRSAEncryption");
		
		//signature par sa propre clé privée
		X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");      
		// DUMP CERTIFICATE AND KEY PAIR      
		//System.out.println(Strings.repeat("=", 80));     
		
		System.out.println("CERTIFICATE TO_STRING");     
		
		System.out.println();     
		System.out.println(cert);     
		System.out.println();      
		System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");     
		System.out.println();     
		PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));     
		pemWriter.writeObject(cert);     
		pemWriter.flush();     
		System.out.println();      
		System.out.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");     
		System.out.println();     
		pemWriter.writeObject(keyPair.getPrivate());     
		pemWriter.flush();     
		System.out.println(); 
		
		return cert;
	}

	
	public static X509Certificate generateSignedCACertificate() throws Exception{

		
		// yesterday     
		Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);     
		
		// in 2 years     
		Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);      
		
		// GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
		KeyPair keyPair = generateRSAKeyPair();    
		
		// GENERATE THE X509 CERTIFICATE
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();     
		
		X500Principal dnName = new X500Principal("CN=John Doe");      
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));     
		certGen.setSubjectDN(dnName);     
		certGen.setIssuerDN(dnName); 
		
		// use the same     
		certGen.setNotBefore(validityBeginDate);     
		certGen.setNotAfter(validityEndDate);     
		
		certGen.setPublicKey(keyPair.getPublic());     
//		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		certGen.setSignatureAlgorithm("MD5WithRSAEncryption");
		
		//signature par sa propre clé privée
		X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");      
		// DUMP CERTIFICATE AND KEY PAIR      
		//System.out.println(Strings.repeat("=", 80));     
		
		System.out.println("CERTIFICATE TO_STRING");     
		//System.out.println(Strings.repeat("=", 80));     
		
		System.out.println();     
		System.out.println(cert);     
		System.out.println();      
		System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");     
		System.out.println();     
		PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));     
		pemWriter.writeObject(cert);     
		pemWriter.flush();     
		System.out.println();      
		System.out.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");     
		System.out.println();     
		pemWriter.writeObject(keyPair.getPrivate());     
		pemWriter.flush();     
		System.out.println(); 
		
		return cert;
	}

	public static X509Certificate generateSignedCertificate(X509Certificate caCert, String datas, BigInteger serial,RSAPrivateKey caPrivateKey, KeyPair pair ) throws Exception{
		X509Certificate cert = null;
		Security.addProvider(new BouncyCastleProvider());
		try{

			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			certGen.setIssuerDN(caCert.getIssuerX500Principal());
			certGen.setNotBefore(new Date(System.currentTimeMillis()));

			certGen.setNotAfter(DateUtils.addYear(new Date(), 10));				    
			certGen.setSubjectDN(new X509Name(datas));
			certGen.setPublicKey(pair.getPublic());
			certGen.setSignatureAlgorithm("MD5WithRSAEncryption");

			certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));

			certGen.addExtension(X509Extensions.SubjectKeyIdentifier,false, new SubjectKeyIdentifierStructure(pair.getPublic()));

			certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

			certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

			//			certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
			certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

			certGen.addExtension(X509Extensions.SubjectAlternativeName, false,
					new GeneralNames(new GeneralName(GeneralName.rfc822Name,datas)));


			certGen.setSerialNumber(serial);	 

			cert = certGen.generate(caPrivateKey);
			System.out.println("\ncertificat"+cert);
			//			cert.get

			// verification du certificat
			try{
				cert.verify(caCert.getPublicKey());
				System.out.println("-->valide /");
				return cert;

			}catch (Exception e) 
			{					
				e.printStackTrace();
				throw new Exception("certificat mal signé par autorité");
			}


		}catch (Exception e) {
			throw new Exception("erreur de generation de certificat:"+e.getMessage()+"\n"+e.getCause()+e.getStackTrace());
		}




	}	

	private static byte[] getSignatureCert(TBSCertificateStructure tbsCert, RSAPrivateKey caPrivateKey) throws Exception{
		MD5Digest digester = new MD5Digest();
		AsymmetricBlockCipher rsa = new PKCS1Encoding(new RSAEngine());

		ByteArrayOutputStream  bOut = new ByteArrayOutputStream();

		DEROutputStream  dOut = new DEROutputStream(bOut);

		dOut.writeObject(tbsCert);

		byte[] signature;

		byte[] certBlock = bOut.toByteArray();

		// first create digest

		digester.update(certBlock, 0, certBlock.length);

		byte[] hash = new byte[digester.getDigestSize()];

		digester.doFinal(hash, 0);

		RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) caPrivateKey;
		RSAPrivateCrtKeyParameters caPrivateKeyParameters = new RSAPrivateCrtKeyParameters(privKey.getModulus(), privKey.getPublicExponent(), privKey.getPrivateExponent(),
				privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(), privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());

		rsa.init(true, caPrivateKeyParameters);

		DigestInfo dInfo = new DigestInfo( new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, null), hash);

		byte[] digest = dInfo.getEncoded(ASN1Encodable.DER);

		signature = rsa.processBlock(digest, 0, digest.length);

		return signature;
	}



	public static File readFile(String strFile){
		File f = new File(strFile);
		return f;
	}

	public static String toHexa(Number n){
		String s = (Long.toHexString(n.longValue())).toUpperCase();

		if (s.length()%2>0 )				
			s="0"+s;

		return s;
	}

	public static Number hexa2Number(String hexa){
		return Long.parseLong(hexa, 16);
	}


	public static void writeX509CertificatePem (String path,X509Certificate cert) throws Exception{

		PEMWriter pemw = new PEMWriter(new FileWriter(path+ Utils.toHexa(cert.getSerialNumber())+".pem"));
		pemw.write(cert.toString());
		pemw.writeObject(cert);


		pemw.close();
	}

	// ecriture de certificats, clés privées, clés publiques
	public static void writeObjetFormatPem (String path,Object o,String name) throws Exception{
		PEMWriter pemw = new PEMWriter(new FileWriter(path+ name));
		pemw.writeObject(o);
		pemw.close();
	}

	public static void createPkcs12(PrivateKey privateKey, String pkcs12Pass, Certificate caCert,Certificate signedCert,String pkcs12Name, String tempPath) throws Exception{


		KeyStore ks = KeyStore.getInstance("PKCS12","BC");

		ks.load(null, null);

		Certificate[] chain = new Certificate[] {signedCert,caCert};

		ks.setKeyEntry(pkcs12Name, privateKey, pkcs12Pass.toCharArray(), chain);

		FileOutputStream fOut = new FileOutputStream(tempPath+File.separator+pkcs12Name+".p12");

		ks.store(fOut, pkcs12Pass.toCharArray());
		fOut.close();

	}


	public static boolean createPkcs12OpenSSL(String OpenSSLPath,String privateKeyPath, String pkcs12Pass, String caCertPath,String certPath,String pkcs12Name, String tempPath) throws Exception{


		Process		p;
		String		fullCommand = OpenSSLPath+"/openssl pkcs12 -export -in "+certPath+" -inkey "+privateKeyPath+ " -certfile "+caCertPath+ " -passout pass:expert -out "+tempPath+File.separator+pkcs12Name+".p12" ;
		System.out.println (fullCommand);

		try
		{
			p = Runtime.getRuntime().exec(fullCommand);
		}
		catch(IOException io)
		{
			System.out.println ("io Error" + io.getMessage ());
			return false;
		}
		return true;

	}

	public static void cryterGPG(String certsPath){


	}


	public static String getMD5(String datas) throws Exception{
		byte[] uniqueKey = datas.getBytes();
		byte[] hash = null;
		hash = MessageDigest.getInstance("MD5").digest(uniqueKey);

		String hexaMd5 =new String(Hex.encode(hash)).toUpperCase(); 

		return hexaMd5;	

	}


	public static String getSignature(String md5Message, PrivateKey privateKey) throws Exception{


		Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding","BC");  
		cipher.init(Cipher.ENCRYPT_MODE,privateKey );         
		byte[] datasSignedBytes = cipher.doFinal(Hex.decode(md5Message));
		return new String(Hex.encode(datasSignedBytes)).toUpperCase();

	}



	public static byte[] getMD5Bytes(String datas) throws Exception{
		byte[] uniqueKey = datas.getBytes();
		byte[] hash = null;
		hash = MessageDigest.getInstance("MD5").digest(uniqueKey);
		return hash;
	}

	public static boolean decodeSignature (String datas, byte[] dataSigned, String algoName,PublicKey publicKey) throws Exception{

		Signature signatureAlgorithm =Signature.getInstance(algoName);

		signatureAlgorithm.initVerify(publicKey);
		signatureAlgorithm.update(getMD5Bytes(datas));
		boolean verify =  signatureAlgorithm.verify(dataSigned); 
		return verify;

	}





}
