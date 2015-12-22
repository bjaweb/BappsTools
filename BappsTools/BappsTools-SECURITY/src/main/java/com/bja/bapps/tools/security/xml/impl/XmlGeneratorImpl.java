package com.bja.bapps.tools.security.xml.impl;

import java.io.StringWriter;
import java.io.Writer;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bja.bapps.tools.core.exceptions.TechnicalException;
import com.bja.bapps.tools.security.xml.IXmlGenerator;

public class XmlGeneratorImpl<T> implements IXmlGenerator<T> {

	private static Logger logger = LoggerFactory.getLogger(XmlGeneratorImpl.class);

	/**
	 * @see IXmlGenerator#getGeneratedXml(Object)
	 */
	@Override
	public String getGeneratedXml(T objectToMarshal) throws SecurityException, TechnicalException {

		Writer writer = new StringWriter();

		try {
			JAXBContext context = JAXBContext.newInstance(objectToMarshal.getClass());
			Marshaller marshaller = context.createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			marshaller.setProperty(Marshaller.JAXB_ENCODING, "iso-8859-1");
			marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);

			marshaller.marshal(objectToMarshal, writer);

		} catch (JAXBException e) {
			logger.error(e.getMessage(), e);
			throw new TechnicalException(e);
		}

		return writer.toString();
	}

}
