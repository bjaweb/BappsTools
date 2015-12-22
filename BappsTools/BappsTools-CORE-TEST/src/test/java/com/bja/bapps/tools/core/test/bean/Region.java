package com.bja.bapps.tools.core.test.bean;



/**
 * 
 * @author ben
 *
 */
public class Region {
	
	private int idRegion;
	private String libelleRegion;
	private String adresse;
	
	public int getIdRegion() {
		return idRegion;
	}
	public void setIdRegion(int idRegion) {
		this.idRegion = idRegion;
	}
	public String getLibelleRegion() {
		return libelleRegion;
	}
	public void setLibelleRegion(String libelleRegion) {
		this.libelleRegion = libelleRegion;
	}
	public String getAdresse() {
		return adresse;
	}
	public void setAdresse(String adresse) {
		this.adresse = adresse;
	}
	@Override
	public String toString() {
		return "Region [libelleRegion=" + libelleRegion + ", adresse="
				+ adresse + "]";
	}
	
	

}
