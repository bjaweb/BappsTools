package com.bja.bapps.tools.security.test;

import java.security.KeyPair;

import com.bja.bapps.tools.security.SecurityException;
import com.bja.bapps.tools.security.Utils;

public class TestUtils {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		
		try {
//			KeyPair pair =  Utils.generateRSAKeyPair();
//			
//			System.out.println(pair.getPrivate());
			

				Utils.generateSignedCACertificate();
			
		} catch (SecurityException e) {
			
			e.printStackTrace();
		}
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		

	}

}
