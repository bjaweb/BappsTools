package com.bja.bapps.tools.core.exceptions;

public class BappsToolsException extends Exception {
	
	private static final long serialVersionUID = 1L; 
	
	/** Parametre du message. */
	protected String[] parameters;

	public String[] getParameters() {
		return parameters;
	}

	public void setParameters(String[] parameters) {
		this.parameters = parameters;
	}

	public BappsToolsException(String message) {
		super(message);
	}

	public BappsToolsException(String message, String[] params) {
		super(message);
		parameters = params;
	}
	
	public BappsToolsException(BappsToolsException cause) {
		super(cause.getMessage(), cause);
		setParameters(cause.getParameters());
	}

	public BappsToolsException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public BappsToolsException(Throwable cause) {
		super(cause);
	}
	
}
