package com.bja.bapps.tools.core.utils.csv;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

public class LireCSV {

	public static void main(String[] args) {

		

		List<String[]> lignes = new ArrayList<String[]>();
		String caractereDeSeparation = ";";

		try {
			
			lignes = lireLeCsv("src/test/java/fichiersTest/fourvarctt_906_2015-02-05.txt");
			
			
			 
			for (String[] strings : lignes) {
			  	System.out.println("champ 1 "+strings[0]);
			  	
			  	System.out.println("champ 4 "+strings[22]);
			}
		
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}

	public static List<String []> lireLeCsv(String chemin) throws IOException{


		List<String[]> lignes = new ArrayList<String[]>();
		String caractereDeSeparation = ";";

		
		
		//Scanner scanner = new Scanner(new File("src/test/java/fichiersTest/fourvarctt_906_2015-02-05.txt"));
		Scanner scanner = new Scanner(new File(chemin));
		
//		Scanner scanner = new Scanner(new File("I:/dev/fichiers/fourvarctt_906_2015-02-05.txt"));
		while (scanner.hasNextLine()) {

			lignes.add(scanner.nextLine().split(caractereDeSeparation));

		}
		
		return lignes;		
	}
	
	
	
	public static HashMap<String, HashMap<String, String>> csvToMap(String chemin) throws IOException{
		
		
		HashMap<String, HashMap<String, String>> mapFournisseur = new HashMap<String, HashMap<String,String>>();
		HashMap<String, String> elemFournisseur = null;

		List<String[]> lignes = new ArrayList<String[]>();
		String caractereDeSeparation = ";";

		
		
		//Scanner scanner = new Scanner(new File("src/test/java/fichiersTest/fourvarctt_906_2015-02-05.txt"));
		Scanner scanner = new Scanner(new File(chemin));
		
		String fournisseurEnCours = null;
		
//		Scanner scanner = new Scanner(new File("I:/dev/fichiers/fourvarctt_906_2015-02-05.txt"));
		while (scanner.hasNextLine()) {
			
			String[] ligne = scanner.nextLine().split(caractereDeSeparation);
			
			String fou = ligne[4];
			
			if(!(fournisseurEnCours.equalsIgnoreCase(fou))){
				elemFournisseur = new HashMap<String, String>();
				// on le rem
			}

		}
		
		return mapFournisseur;		
	}

	

}
