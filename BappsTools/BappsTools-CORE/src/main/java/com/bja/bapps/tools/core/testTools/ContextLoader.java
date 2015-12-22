package com.bja.bapps.tools.core.testTools;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import com.bja.bapps.tools.core.testTools.pojos.DatabaseInformationForTest;

public class ContextLoader implements IContextLoader {

	public static ApplicationContext context;

	private String [] springConfigFiles;

	private List<DatabaseInformationForTest> databasesInformationForTest;

	public ContextLoader() {
	}

	public ContextLoader(DatabaseInformationForTest databaseInformationForTest, String [] springConfigFiles) {
		super();
		this.databasesInformationForTest = new ArrayList<DatabaseInformationForTest>();
		this.databasesInformationForTest.add(databaseInformationForTest);
		this.springConfigFiles = springConfigFiles;
	}

	public ContextLoader(DatabaseInformationForTest databaseInformationForTest, String springConfigFiles) {
		super();
		this.databasesInformationForTest = new ArrayList<DatabaseInformationForTest>();
		this.databasesInformationForTest.add(databaseInformationForTest);
		this.springConfigFiles = springConfigFiles.split(";");
	}

	public ContextLoader(List<DatabaseInformationForTest> databasesInformationForTest, String [] springConfigFiles) {
		super();
		this.databasesInformationForTest = databasesInformationForTest;
		this.springConfigFiles = springConfigFiles;
	}

	public ContextLoader(List<DatabaseInformationForTest> databasesInformationForTest, String springConfigFiles) {
		super();
		this.databasesInformationForTest = databasesInformationForTest;
		this.springConfigFiles = springConfigFiles.split(";");
	}

	private void generateDatabase(DatabaseInformationForTest databaseInformationForTest) throws IOException, ClassNotFoundException, SQLException {
		Connection connection = databaseConnection(databaseInformationForTest);
		Statement statement = connection.createStatement();
		statement.execute(getSqlFileContent(databaseInformationForTest));
		statement.close();
		connection.close();
	}

	private Connection databaseConnection(DatabaseInformationForTest databaseInformationForTest) throws ClassNotFoundException, SQLException {
		Class.forName(databaseInformationForTest.getDriverClass());
		return DriverManager.getConnection(databaseInformationForTest.getDatabaseUrl());
	}

	private String getSqlFileContent(DatabaseInformationForTest databaseInformationForTest) throws FileNotFoundException, IOException {
		StringBuffer fileContent = new StringBuffer();
		BufferedReader bufferedReader = new BufferedReader(new FileReader(databaseInformationForTest.getSchemeFile()));
		while (bufferedReader.ready()) {
			fileContent.append(bufferedReader.readLine());
			//fileContent.append("\n");
		}
		return fileContent.toString();
	}

	public ApplicationContext getContext() throws IOException, ClassNotFoundException, SQLException {
		if (context == null) {
			if (databasesInformationForTest != null) {
				for (DatabaseInformationForTest databaseInformationForTest : databasesInformationForTest) {
					if (databaseInformationForTest.getSchemeFile() != null) {
						generateDatabase(databaseInformationForTest);
					}
				}
			}
			context = new ClassPathXmlApplicationContext(springConfigFiles);
		}
		return context;
	}

}
