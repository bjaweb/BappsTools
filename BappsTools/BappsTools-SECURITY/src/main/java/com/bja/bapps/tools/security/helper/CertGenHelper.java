package com.bja.bapps.tools.security.helper;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import com.bja.bapps.tools.core.utils.dataType.DateUtils;

public class CertGenHelper {

	private HashMap<String, String> datas;
	
	//CN : common name
	private String nom;
	
	// O Organisation
	private String organisation;
	
	//OU (Organisation Unit) (Service dans la societe)
	private String serviceSociete;

	//L (Locality/City)
	private String ville;
	
	//ST (State/Province)
	private String province;
	
	//C (Country : code du pays ex FR)
	private String pays; 
	
	//CA
	private String email;
	
	
	private Date dateDeb;
	private Date dateFin;
	/*
	 * givenName Prénom de la personne 
	 * postalAddress Adresse postale (sans le code postal) 
postalCode Code postal 

	 * 
	 * 
	 */
	
	
	public CertGenHelper(String nom){
		
		//par defaut la date de but est hier
		this(nom, new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
	}
	
	public CertGenHelper(String nom, Date dateDebut){
//		// in 2 years     
//		Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);
		
		//par defaut la date de but est hier
		this(nom, dateDebut,new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));

		
	}
	
	public CertGenHelper(String nom, Date dateDebut, Date dateFin){
		this.nom = nom;
		this.dateDeb = dateDebut;
		this.dateFin= dateFin;
	}
	
	private String getDatas(){
	StringBuffer datas = new StringBuffer("CN="+this.getNom());	
	//datas.append(this.email==null?"":",CA="+this.getEmail());
	datas.append(this.email==null?"":",emailAddress="+this.getEmail());
	
	
	datas.append(this.organisation==null?"":",O="+this.getOrganisation());
	datas.append(this.serviceSociete==null?"":",OU="+this.getServiceSociete());
	datas.append(this.ville==null?"":",L="+this.getVille());
	
	datas.append(this.province==null?"":",ST="+this.getProvince());
	datas.append(this.pays==null?"":",C="+this.getPays());
	
	return datas.toString();
	}
	
	
	public X509V1CertificateGenerator certGenV1(){

		X509V1CertificateGenerator certGen  = new X509V1CertificateGenerator();
		
		
		X500Principal dnName = new X500Principal(getDatas());      
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));     
		certGen.setSubjectDN(dnName);     
		certGen.setIssuerDN(dnName); 
		
		// use the same     
		certGen.setNotBefore(this.dateDeb);     
		certGen.setNotAfter(this.dateFin);     
		
		return certGen;
		
	}

	public X509V3CertificateGenerator certGenV3(X509Certificate caCert){
		/*
		 * 		    
			
			certGen.setPublicKey(pair.getPublic());
			certGen.setSignatureAlgorithm("MD5WithRSAEncryption");


			cert = certGen.generate(caPrivateKey);
			System.out.println("\ncertificat"+cert);
			//			cert.get


		 * 
		 */
		
		X509V3CertificateGenerator certGen  = new X509V3CertificateGenerator();
		
		
		X500Principal dnName = new X500Principal(getDatas());      
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		
		certGen.setSubjectDN(dnName);     
		certGen.setIssuerDN(caCert.getIssuerX500Principal()); 
		
		// use the same     
		certGen.setNotBefore(this.dateDeb);     
		certGen.setNotAfter(this.dateFin);     
		     
		certGen.setSignatureAlgorithm("MD5WithRSAEncryption");
		
		
	

		
		return certGen;
		
	}

	
	
	public String getNom() {
		return nom;
	}

	public void setNom(String nom) {
		this.nom = nom;
	}

	public String getOrganisation() {
		return organisation;
	}

	public void setOrganisation(String organisation) {
		this.organisation = organisation;
	}

	public String getServiceSociete() {
		return serviceSociete;
	}

	public void setServiceSociete(String serviceSociete) {
		this.serviceSociete = serviceSociete;
	}

	public String getVille() {
		return ville;
	}

	public void setVille(String ville) {
		this.ville = ville;
	}

	public String getProvince() {
		return province;
	}

	public void setProvince(String province) {
		this.province = province;
	}

	public String getPays() {
		return pays;
	}

	public void setPays(String pays) {
		this.pays = pays;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}


	
}
