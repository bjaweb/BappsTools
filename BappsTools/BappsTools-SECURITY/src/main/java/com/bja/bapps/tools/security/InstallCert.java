package com.bja.bapps.tools.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class InstallCert {
	
	 public static void main(String[] args) throws Exception {
			String host = "localhost";
			int port = 80;
			char[] passphrase = null;//"".toCharArray();

			System.out.println("InstallCert.main()" + System.getProperty("java.home"));
			
			File file = new File("jssecacerts");
			if (!file.exists() || !file.isFile()) {
			    char SEP = File.separatorChar;
			    File dir = new File(System.getProperty("java.home") + SEP
				    + "lib" + SEP + "security");
			    file = new File(dir, "jssecacerts");
			    if (!file.exists() || !file.isFile()) {
				file = new File(dir, "cacerts");
			    }
			}
			System.out.println("Loading KeyStore " + file.getAbsolutePath() + "...");
			InputStream in = new FileInputStream(file);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(in, passphrase);
			in.close();

			Enumeration<String> aliases = ks.aliases();
			
			while(aliases.hasMoreElements()){
				String alias = aliases.nextElement();
				
				Key key= ks.getKey(alias, null);
				System.out.println("key "+key);
//					System.out.println("alias "+alias);
				
				  Certificate cert = ks.getCertificate(alias);
//				  System.out.println("cert "+cert);
			}
			
			
			SSLContext context = SSLContext.getInstance("TLS");
			TrustManagerFactory tmf =
			    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ks);
			X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
			SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
			context.init(null, new TrustManager[] {tm}, null);
			SSLSocketFactory factory = context.getSocketFactory();
			
			//
			
			RSAPrivateKey caPrivatekey=  Utils.loadClientKey("D:/tmp/cert/bjawebPrivKey", null);
			RSAPrivateKey certPrivatekey=  Utils.loadClientKey("D:/tmp/cert/bjanvionPrivKey", null);
			
			System.out.println("private cakey "+caPrivatekey);
			
			X509Certificate caCert=Utils.readCertificate("D:/tmp/cert/bjaweb.pem");
			X509Certificate cert = Utils.readCertificate("D:/tmp/cert/bjanvionCert.pem");
			System.out.println("caCert "+caCert);
			
			
			
			ks.setCertificateEntry("bjanvionCert", cert);
			java.security.cert.Certificate[] chain = {cert,caCert};
			ks.setKeyEntry("bjanvionCert", cert.getPublicKey().getEncoded(), chain);
			
			
			
//			System.out.println("Opening connection to " + host + ":" + port + "...");
//			SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
//			socket.setSoTimeout(10000);
//			try {
//			    System.out.println("Starting SSL handshake...");
//			    socket.startHandshake();
//			    socket.close();
//			    System.out.println();
//			    System.out.println("No errors, certificate is already trusted");
//			} catch (SSLException e) {
//			    System.out.println();
//			    e.printStackTrace(System.out);
//			}

//			X509Certificate[] chain = tm.chain;
//			if (chain == null) {
//			    System.out.println("Could not obtain server certificate chain");
//			    return;
//			}

			BufferedReader reader =
				new BufferedReader(new InputStreamReader(System.in));

//			System.out.println();
//			System.out.println("Server sent " + chain.length + " certificate(s):");
//			System.out.println();
//			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
//			MessageDigest md5 = MessageDigest.getInstance("MD5");
//			for (int i = 0; i < chain.length; i++) {
//			    X509Certificate cert = chain[i];
//			    System.out.println
//			    	(" " + (i + 1) + " Subject " + cert.getSubjectDN());
//			    System.out.println("   Issuer  " + cert.getIssuerDN());
//			    sha1.update(cert.getEncoded());
//			    System.out.println("   sha1    " + toHexString(sha1.digest()));
//			    md5.update(cert.getEncoded());
//			    System.out.println("   md5     " + toHexString(md5.digest()));
//			    System.out.println();
//			}

//			System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
//			String line = reader.readLine().trim();
//			int k;
//			try {
//			    k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
//			} catch (NumberFormatException e) {
//			    System.out.println("KeyStore not changed");
//			    return;
//			}
//
//			X509Certificate cert = chain[k];
//			String alias = host + "-" + (k + 1);
//			ks.setCertificateEntry(alias, cert);
//
//			OutputStream out = new FileOutputStream(file);
//			ks.store(out, passphrase);
//			out.close();
//
//			System.out.println();
//			System.out.println(cert);
//			System.out.println();
//			System.out.println
//				("Added certificate to keystore " + file.getAbsolutePath()  + " using alias '"
//				+ alias + "'");
		    }

		    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

		    private static String toHexString(byte[] bytes) {
			StringBuilder sb = new StringBuilder(bytes.length * 3);
			for (int b : bytes) {
			    b &= 0xff;
			    sb.append(HEXDIGITS[b >> 4]);
			    sb.append(HEXDIGITS[b & 15]);
			    sb.append(' ');
			}
			return sb.toString();
		    }

		    private static class SavingTrustManager implements X509TrustManager {

			private final X509TrustManager tm;
			private X509Certificate[] chain;

			SavingTrustManager(X509TrustManager tm) {
			    this.tm = tm;
			}

			public X509Certificate[] getAcceptedIssuers() {
			    throw new UnsupportedOperationException();
			}

			public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			    throw new UnsupportedOperationException();
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			    this.chain = chain;
			    tm.checkServerTrusted(chain, authType);
			}
		  }

}
