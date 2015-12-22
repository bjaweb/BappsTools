package com.bja.bapps.tools.core.testTools.pojos;

import java.io.File;

public class DatabaseInformationForTest {

	private String driverClass;
	private String databaseUrl;
	private String user;
	private String password;
	private File schemeFile;

	public DatabaseInformationForTest() {
	}
	
	public DatabaseInformationForTest(String driverClass, String databaseUrl, String user, String password, File schemeFile) {
		super();
		this.driverClass = driverClass;
		this.databaseUrl = databaseUrl;
		this.user = user;
		this.password = password;
		this.schemeFile = schemeFile;
	}

	public DatabaseInformationForTest(String driverClass, String databaseUrl, File schemeFile) {
		this(driverClass, databaseUrl, null, null, schemeFile);
	}

	public String getDriverClass() {
		return driverClass;
	}

	public void setDriverClass(String driverClass) {
		this.driverClass = driverClass;
	}

	public String getDatabaseUrl() {
		return databaseUrl;
	}

	public void setDatabaseUrl(String databaseUrl) {
		this.databaseUrl = databaseUrl;
	}

	public File getSchemeFile() {
		return schemeFile;
	}

	public void setSchemeFile(File schemeFile) {
		this.schemeFile = schemeFile;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
