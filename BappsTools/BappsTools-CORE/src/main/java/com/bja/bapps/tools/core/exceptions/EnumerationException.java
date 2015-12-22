package com.bja.bapps.tools.core.exceptions;


public class EnumerationException extends TechnicalException {

	private static final long serialVersionUID = 1L;

	public EnumerationException(String message) {
		super(message);
	}

	public EnumerationException(String message, String[] params) {
		super(message);
		parameters = params;
	}
	
	public EnumerationException(BappsToolsException e) {
		super(e);
	}
	
	public EnumerationException(Throwable e) {
		super(e);
	}
	
	public EnumerationException(String message, Throwable cause) {
		super(message, cause);
	}

}
