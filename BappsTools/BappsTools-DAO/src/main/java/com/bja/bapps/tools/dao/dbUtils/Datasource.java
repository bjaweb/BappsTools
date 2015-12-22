package com.bja.bapps.tools.dao.dbUtils;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import com.bja.bapps.tools.dao.exceptions.DaoException;


public class Datasource {

	private Connection connection;
	
	private static final String CONFIG_URL="url";
	private static final String CONFIG_DRIVER="driverClass";
	private static final String CONFIG_PASSWORD="password";
	private static final String CONFIG_USERNAME="username";

	private static Datasource instance;

	private String url;
	private String driver;
	private String password;
	private String username;

	private Datasource() {	}	


	public static Datasource getInstance(Properties properties) throws DaoException {
		if (instance == null ) {
			try {
				instance = new Datasource();

				instance.url = properties.getProperty(CONFIG_URL, "");
				instance.driver = properties.getProperty(CONFIG_DRIVER, "");
				instance.username = properties.getProperty(CONFIG_USERNAME, "");
				instance.password = properties.getProperty(CONFIG_PASSWORD, "");
				
				System.out.println("instance.url "+instance.url);
				System.out.println("instance.driver "+instance.driver);
				System.out.println("instance.username "+instance.username);
				System.out.println("instance.password "+instance.password);

				Class.forName(instance.driver).newInstance();
				
				instance.getConnection();
			} catch (Exception e) {e.printStackTrace();
				throw new DaoException(
						"erreur de connexion à la base : \n" + "url :"
						+ instance.url + "\ndriver:" + instance.driver
						+ "\nusername:" + instance.username
						+ " / password:" + instance.password);
			}

		}

		return instance;

	}

	public Connection getConnection()throws SQLException {

		if(connection == null || connection.isClosed()){

			try {
				System.out.println(url);
				System.out.println(username);
				System.out.println(password);
				connection = DriverManager.getConnection(url, username, password);	    		    
			} 
			catch (Exception e) {
				e.printStackTrace();
				throw new SQLException("Erreur impossible de recuperer la connexion "+e.getMessage());
			}


		}
		return connection;
	}
	
	
	public void closeConnection(){
    	try{
    		connection.close();
    	}catch (Exception e) {}
    }
    
    
    protected void finalize() throws Throwable {    	
    	super.finalize();
    	this.closeConnection();
    }


}
