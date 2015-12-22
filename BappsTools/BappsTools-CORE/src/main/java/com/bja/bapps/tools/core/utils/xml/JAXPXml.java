package com.bja.bapps.tools.core.utils.xml;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathExpression;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class JAXPXml {

	private static Logger logger = LoggerFactory.getLogger(JAXPXml.class);
	
	public static String getNodeValue(Document document,String nodeName){
		String valeur=null;
		
			try {
				NodeList nodes = document.getElementsByTagName(nodeName);
				
				if(nodes!=null && nodes.item(0)!=null && nodes.item(0).getChildNodes()!=null)
					valeur=nodes.item(0).getChildNodes().item(0).getNodeValue();

			} 
			catch (Exception e) {
				logger.error(e.getMessage(),e);
			}
		
		return valeur;
	}
	public static void main(String[] args)  {
	  try {
		
		// Standard of reading a XML file
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    factory.setNamespaceAware(true);
	    DocumentBuilder builder = factory.newDocumentBuilder();;
	    Document doc = builder.parse("c:/test2.xml");
	    doc.getDocumentElement().normalize();

		System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
	    
	    XPathExpression expr = null;
	    	    
	    System.out.println("OK"+getNodeValue(doc, "reg_champ1"));
	    
	    
		
	    
		} catch (Exception e) {
			// TODO: handle exception
		}

	}

}
