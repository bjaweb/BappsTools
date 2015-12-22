package com.bja.bapps.tools.core.utils.xml;

import java.io.File;
import java.io.IOException;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.DOMOutputter;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class JDomParser {


	private static Logger logger = LoggerFactory.getLogger(JDomParser.class);
	private Document document;

	// pour creer des nouveaux doc XML
	public JDomParser() {
	
	}
	
	public JDomParser(Document document) {
		super();
		this.document = document;
	}



	public JDomParser(String pathFichierXML) throws JDOMException, IOException {
		SAXBuilder sxb = new SAXBuilder();

		//On crée un nouveau document JDOM avec en argument le fichier XML
		//Le parsing est terminé ;)
		document = sxb.build(new File(pathFichierXML));

	}



	public void afficheDocument(){afficheDocument(null);}

//	public void afficheDocument(String formatName)
//	{
//		try
//		{
//			//On utilise ici un affichage classique avec getPrettyFormat() pour passage à la ligne auto
//			XMLOutputter sortie = new XMLOutputter(Format.getPrettyFormat());
//			if(formatName !=null && formatName.trim().length()>0){
//				Format format = sortie.getFormat();
//				format.setEncoding(formatName);
//			}
//			sortie.output(document, System.out);
//		}
//		catch (java.io.IOException e){logger.error(e.getMessage());}
//	}

	public void afficheDocument(CharSetXML formatName)
	{
		if(document == null){
			logger.info("aucun document a afficher");
			return;
		}
		try
		{
			//On utilise ici un affichage classique avec getPrettyFormat() pour passage à la ligne auto
			XMLOutputter sortie = new XMLOutputter(Format.getPrettyFormat());
			if(formatName !=null){
				Format format = sortie.getFormat();
				format.setEncoding(formatName.getValue());
			}
			sortie.output(document, System.out);
		}
		catch (java.io.IOException e){logger.error(e.getMessage());}
	}

	// DOM
	public org.w3c.dom.Document getDocumentDOM(){
		try{
			Element racine = document.getRootElement();
			DOMOutputter domOutputter = new DOMOutputter();		
			return  domOutputter.output(document);
		}catch (Exception e){
			logger.error("impossible de recuperer l'outputteur dom",e);
			return null;
		}
	}
	
	
	public int numberOfNode(String nodeName){
		
		return getElementsByTagName(nodeName).getLength();
//		int numberOfNode = 0;
//		try {
//			return getDocumentDOM().getElementsByTagName(nodeName).getLength();
//		} catch (Exception e) {
//			logger.error("impossible de compter les noeuds");
//			return 0;
//		}
	}

	
	public String getNodeValue(String nodeName){
		String valeur=null;
		
			try {
				NodeList nodes = getDocumentDOM().getElementsByTagName(nodeName);
				
				if(nodes!=null && nodes.item(0)!=null && nodes.item(0).getChildNodes()!=null)
					valeur=nodes.item(0).getChildNodes().item(0).getNodeValue();

			} 
			catch (Exception e) {
				logger.error(e.getMessage(),e);
			}
		
		return valeur;
	}
	
	private NodeList getElementsByTagName(String tagName){
		
			try {
				return  getDocumentDOM().getElementsByTagName(tagName);
			} catch (Exception e) {
				logger.error("recuperation nodeList impossible ",e);
				logger.debug("retour liste vide");
				return new NodeList() {
					
					public Node item(int arg0) {
						// TODO Auto-generated method stub
						return null;
					}
					
					public int getLength() {
						// TODO Auto-generated method stub
						return 0;
					}
				};
			}
	}
	
	
//	public void insertPiecesJointes(String[] liste,String nodeName, String uri){
//		//1ère étape : Suppression des balises piecejointe
//		//déjà présentes dans le fichier xml
//		org.w3c.dom.Document documentDom = getDocumentDOM();
//		
//		NodeList nodesPJ=getElementsByTagName(nodeName);
//		int compteur=nodesPJ.getLength();
//		
//				
//		while(compteur>0){
//		Node courant=nodesPJ.item(0);
//		courant.getParentNode().removeChild(courant);
//		nodesPJ=documentDom.getElementsByTagName(nodeName);
//		compteur=nodesPJ.getLength();
//		}
//				
//			
//		//2ème étape : Ajout des nouvelles balises piecejointe
//		NodeList nodes=documentDom.getElementsByTagName("lettre");
//		Text pjValue;
//		if(nodes!=null && liste!=null)
//		for(int i=0; i<nodes.getLength(); i++)
//		{
//			for(int j=0; j<liste.length; j++)
//			{
//				org.w3c.dom.Element piecejointe = documentDom.createElement("piecejointe");
//				nodes.item(i).appendChild(piecejointe);
//				pjValue  = documentDom.createTextNode(liste[j]);
//				piecejointe.appendChild(pjValue);
//				
//			}
//			
//		}
//		
//		
//			
//			File file=new File(uri);
//			file.delete();
//			try{
//			write(DOMtoJDOM(documentDom),uri);
//			}
//			catch (Exception e) {
//				logger.error(e.getMessage(),e);
//			}
//		
//
//			
//	}


	public static void main(String[] args) {

		logger.debug("lancement du prog");
		try {
//			JDomParser j = new JDomParser();
			JDomParser j = new JDomParser("c:/test2.xml");
			String format = " ";
			j.afficheDocument(CharSetXML.ISO885915);
			//			j.afficheDocument();
			
			logger.debug("nb node "+j.numberOfNode("rapport"));
			logger.debug("node value "+j.getNodeValue("libelle_rapport"));
			

		} catch (Exception e) {
			logger.error(e.getMessage(),e);
		}



	}


}
