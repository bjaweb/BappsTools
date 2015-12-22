package com.bja.bapps.tools.core;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


@XmlRootElement(name = "BD")
 public class BD extends Book{

	private String publicVise;
	private boolean zzc;
	public String getPublicVise() {
		return publicVise;
	}
	public void setPublicVise(String publicVise) {
		this.publicVise = publicVise;
	}
	public boolean isZzc() {
		return zzc;
	}
	public void setZzc(boolean zzc) {
		this.zzc = zzc;
	}
	
	
} 