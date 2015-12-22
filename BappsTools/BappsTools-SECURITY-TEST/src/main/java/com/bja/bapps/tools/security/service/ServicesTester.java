package com.bja.bapps.tools.security.service;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import com.bja.bapps.tools.core.testTools.ContextLoader;
import com.bja.bapps.tools.core.testTools.pojos.DatabaseInformationForTest;


public class ServicesTester {
	public ContextLoader contextLoader;

	public DatabaseInformationForTest databaseInformation;

	public void initTester() throws IOException {
		initTester("/testEnvironnement.properties");
	}
	
	public void initTester(String resource) throws IOException {

		Properties properties = new Properties();
		InputStream inputStream = this.getClass().getResourceAsStream(resource);
		properties.load(inputStream);
		
		databaseInformation = new DatabaseInformationForTest(
				properties.getProperty("driverClass"), 
				properties.getProperty("url"),
				properties.getProperty("username"),
				properties.getProperty("password"),
				null
		);

		contextLoader = new ContextLoader(
				databaseInformation, 
				properties.getProperty("appliContexte")
		);
	}
}
