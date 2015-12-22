package com.bja.bapps.tools.core.exceptions;


public class DataFormatException extends TechnicalException {
	private static final long serialVersionUID = 1L;

	public DataFormatException(String message) {
		super(message);
	}

	public DataFormatException(String message, String[] params) {
		super(message);
		parameters = params;
	}
	
	public DataFormatException(BappsToolsException e) {
		super(e);
	}
	
	public DataFormatException(Throwable e) {
		super(e);
	}

	public DataFormatException(String message, Throwable cause) {
		super(message, cause);
	}
}
