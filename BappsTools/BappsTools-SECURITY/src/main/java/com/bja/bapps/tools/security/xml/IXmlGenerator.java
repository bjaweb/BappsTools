package com.bja.bapps.tools.security.xml;


import com.bja.bapps.tools.core.exceptions.TechnicalException;

public interface IXmlGenerator<T> {

	/**
	 * Get the xml generated from an object 
	 * @param objectToMarshal
	 * @return
	 * @throws SecurityException
	 * @throws TechnicalException
	 */
	public String getGeneratedXml(T objectToMarshal) throws SecurityException, TechnicalException;

}
