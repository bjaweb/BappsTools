package com.bja.bapps.tools.core.exceptions;

public class TechnicalException extends BappsToolsException {

	private static final long serialVersionUID = -8552633182944241620L;

	public TechnicalException(String message) {
		super(message);
	}

	public TechnicalException(String message, String[] params) {
		super(message);
		parameters = params;
	}

	public TechnicalException(BappsToolsException cause) {
		super(cause);
	}

	public TechnicalException(Throwable cause) {
		super(cause);
	}

	public TechnicalException(String message, Throwable cause) {
		super(message, cause);
	}

}
