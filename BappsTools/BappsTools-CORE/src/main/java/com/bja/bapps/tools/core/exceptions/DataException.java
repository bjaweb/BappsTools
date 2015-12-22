package com.bja.bapps.tools.core.exceptions;


public class DataException extends TechnicalException {

	private static final long serialVersionUID = 1L;

	public DataException(String message) {
		super(message);
	}

	public DataException(String message, String[] params) {
		super(message);
		parameters = params;
	}
	
	public DataException(BappsToolsException e) {
		super(e);
	}
	
	public DataException(Throwable e) {
		super(e);
	}

	public DataException(String message, Throwable cause) {
		super(message, cause);
	}
}
