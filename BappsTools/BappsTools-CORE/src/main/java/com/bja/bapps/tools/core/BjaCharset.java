package com.bja.bapps.tools.core;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.util.Scanner;
import java.util.SortedMap;

import org.apache.commons.io.FileUtils;

import com.bja.bapps.tools.core.utils.files.impl.FilesUtilsImpl;

public class BjaCharset {


	
	public static void main(String[] args) {
		try {
//			afficheCharset();
			
			System.out.println("lecture fichier ben");
			readFile2("ben2.txt");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void readFile(String path) throws Exception{
		
//		FileReader reader = new FileReader(path);
		File file = new File(path);
		System.out.println(file.getAbsolutePath());
		Scanner scanner = new Scanner(file);
		while (scanner.hasNext())
			System.out.println(scanner.next());
		
		
	}
	public static void readFile2(String path) throws Exception{
		
//		FileReader reader = new FileReader(path);
		File file = new File(path);
		
		String s = FileUtils.readFileToString(file, "UTF-8");
		System.out.println(s);
		
		String s2 = FileUtils.readFileToString(file,"ISO-8859-1");
		System.out.println(s2);
		byte b[] =s.getBytes();
		
		System.out.println(new String(b));
//		Scanner scanner = new Scanner(file, "ISO-8859-1");
//		Scanner scanner = new Scanner(file, "UTF-8");
//		while (scanner.hasNext())
//			System.out.println(scanner.next());
		
		
	}

	public static void afficheCharset() throws Exception{
		PrintWriter pw = new PrintWriter(new File("charset.txt"));
		
		SortedMap<String,Charset> charsets = Charset.availableCharsets();
		for(String nom : charsets.keySet()){
			System.out.println("Charset "+nom);
			pw.write("Charset "+nom);
			Charset charset = charsets.get(nom);
			for(String alias : charset.aliases()){
				System.out.print(" "+alias+",");
				pw.write(" "+alias+",");
			}
			System.out.println();
			pw.write("\n");
		}
		pw.close();
	}

}
