package com.bja.bapps.tools.dao.exceptions;

import com.bja.bapps.tools.core.exceptions.BappsToolsException;


public class DaoException extends BappsToolsException {

	private static final long serialVersionUID = -8552633182944241620L;

	public DaoException(String message) {
		super(message);
	}

	public DaoException(String message, String[] params) {
		super(message);
		parameters = params;
	}

	public DaoException(BappsToolsException cause) {
		super(cause);
	}

	public DaoException(Throwable cause) {
		super(cause);
	}

	public DaoException(String message, Throwable cause) {
		super(message, cause);
	}

}
