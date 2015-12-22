package com.bja.bapps.tools.security;

import org.bouncycastle.openssl.PasswordFinder;


 class DefaultPasswordFinder implements PasswordFinder {
	 
	 private final char [] password;

	    public DefaultPasswordFinder(char [] password) {
	        this.password = password;
	    }

		public char[] getPassword() {
			// TODO Auto-generated method stub
			return password;
		}
 }
