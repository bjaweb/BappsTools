package com.bja.bapps.tools.core.testTools.DAO;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import com.bja.bapps.tools.core.testTools.pojos.DatabaseInformationForTest;

public class DbUtils {

	public DbUtils() {
	}

	private static Connection databaseConnection(String dbDriver, String dbUrl, String user, String password) throws Exception {
		Class.forName(dbDriver);
		Connection connection = null;
		if (user != null && password != null) {
			connection = DriverManager.getConnection(dbUrl, user, password);
		} else {
			connection = DriverManager.getConnection(dbUrl);
		}
		return connection;
	}
	
	private static void executeFileContent(Connection connection, File file) throws Exception {
		
		StringBuffer commandBuffer = new StringBuffer();
		BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
		Statement statement = null;
		while (bufferedReader.ready()) {
			commandBuffer.append(bufferedReader.readLine());
			if (commandBuffer.length() > 1 && commandBuffer.substring(commandBuffer.length() - 1).equals(";")) {
				statement = connection.createStatement();
				commandBuffer.deleteCharAt(commandBuffer.length() - 1);
				statement.execute(commandBuffer.toString());
				commandBuffer = new StringBuffer();
				statement.close();
			}
		}
	}

	public static void executeScript(File sqlFile, String dbDriver, String dbUrl, String user, String password) throws Exception {
		Connection connection = databaseConnection(dbDriver, dbUrl, user, password);
		//statement.executeUpdate(getSqlFileContent(sqlFile));
		executeFileContent(connection, sqlFile);
		connection.close();
		Thread.sleep(5);
	}

	public static void executeScript(File sqlFile, String dbDriver, String dbUrl) throws Exception {
		executeScript(
				sqlFile, 
				dbDriver, 
				dbUrl, 
				null, 
				null
		);
	}

	public static void executeScript(File sqlFile, DatabaseInformationForTest databaseInformationForTest) throws Exception {
		executeScript(
				sqlFile, 
				databaseInformationForTest.getDriverClass(), 
				databaseInformationForTest.getDatabaseUrl(), 
				databaseInformationForTest.getUser(), 
				databaseInformationForTest.getPassword()
		);
	}

}
