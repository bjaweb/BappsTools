package com.bja.bapps.tools.security;

import com.bja.bapps.tools.core.exceptions.BappsToolsException;




public class SecurityException extends BappsToolsException {

	private static final long serialVersionUID = -8552633182944241620L;

	public SecurityException(String message) {
		super(message);
	}

	public SecurityException(String message, String[] params) {
		super(message);
		parameters = params;
	}

	public SecurityException(BappsToolsException cause) {
		super(cause);
	}

	public SecurityException(Throwable cause) {
		super(cause);
	}

	public SecurityException(String message, Throwable cause) {
		super(message, cause);
	}

}
