package com.bja.bapps.tools.core.jaxb;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URL;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class JaxBUtils {
	
	 public static <T> T parse(URL url, Class<T> clazz) throws JAXBException {
	        Unmarshaller unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
	        return clazz.cast(unmarshaller.unmarshal(url));
	    }
		
	 public static <T> T parse(String path, Class<T> clazz) throws JAXBException, FileNotFoundException {
	        Unmarshaller unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
	        return clazz.cast(unmarshaller.unmarshal(new FileReader(path)));
	    }
	 
	 public static <T> T parse(URL url, Class<T> clazz, JAXBContext context) throws JAXBException {
	        Unmarshaller unmarshaller = context.createUnmarshaller();
	        return clazz.cast(unmarshaller.unmarshal(url));
	    }
		
	 public static <T> T parse(String path, Class<T> clazz,JAXBContext context) throws JAXBException, FileNotFoundException {
	        Unmarshaller unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
	        return clazz.cast(unmarshaller.unmarshal(new FileReader(path)));
	    }


}
