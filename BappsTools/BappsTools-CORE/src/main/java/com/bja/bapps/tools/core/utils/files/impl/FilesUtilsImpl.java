package com.bja.bapps.tools.core.utils.files.impl;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.zip.Adler32;
import java.util.zip.CheckedOutputStream;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bja.bapps.tools.core.exceptions.TechnicalException;
import com.bja.bapps.tools.core.utils.dataType.ByteUtils;
import com.bja.bapps.tools.core.utils.dataType.StringUtils;
import com.bja.bapps.tools.core.utils.files.IFileUtils;

/**
 * @author bjanvion
 *
 */
public class FilesUtilsImpl implements IFileUtils {


	private static Logger logger = LoggerFactory.getLogger(FilesUtilsImpl.class);


	/**
	 * compression d'un repertoire ou d'un fichier. 
	 * Le repertoire present dans un repertoire à compresser ne sera pas compresser
	 * @param FileOrDirpath
	 * @return
	 * @throws Exception
	 */
	public static void zip(String FileOrDirpath) throws Exception{


		// création d'un flux d'écriture sur fichier
		FileOutputStream dest = new FileOutputStream(FileOrDirpath+".zip");		
		CheckedOutputStream checksum = new CheckedOutputStream(dest, new Adler32());
		// création d'un buffer d'écriture
		BufferedOutputStream buff = new BufferedOutputStream(checksum);

		// création d'un flux d'écriture Zip
		ZipOutputStream out = new ZipOutputStream(buff);


		// spécification de la méthode de compression
		out.setMethod(ZipOutputStream.DEFLATED);

		// spécifier la qualité de la compression 0..9
		out.setLevel(Deflater.BEST_COMPRESSION);


		addingFiles(new File(FileOrDirpath), out);


		// fermeture du flux d'écriture
		out.close();
		buff.close();
		checksum.close();
		dest.close();



	}

	public static void zip(String FileOrDirpath, String destinationDir) throws Exception{

		// création d'un flux d'écriture sur fichier
		FileOutputStream dest = new FileOutputStream(destinationDir+"/"+new File(FileOrDirpath).getName()+".zip");		
		CheckedOutputStream checksum = new CheckedOutputStream(dest, new Adler32());
		// création d'un buffer d'écriture
		BufferedOutputStream buff = new BufferedOutputStream(checksum);

		// création d'un flux d'écriture Zip
		ZipOutputStream out = new ZipOutputStream(buff);


		// spécification de la méthode de compression
		out.setMethod(ZipOutputStream.DEFLATED);

		// spécifier la qualité de la compression 0..9
		out.setLevel(Deflater.BEST_COMPRESSION);


		addingFiles(new File(FileOrDirpath), out);


		// fermeture du flux d'écriture
		out.close();
		buff.close();
		checksum.close();
		dest.close();

	}

	private static void addingFiles(File directoryOrFile, ZipOutputStream zipOut) throws Exception{
		// buffer temporaire des données à écriture dans le flux de sortie
		byte data[] = new byte[BUFFER];

		if(directoryOrFile.isDirectory()){

			File files[] = directoryOrFile.listFiles();


			for (File file:files) {
				if(file.isFile())
					addingFile(file, zipOut, data);
			}
		}
		else addingFile(directoryOrFile, zipOut, data);

	}


	private static void addingFile(File file, ZipOutputStream zipOut, byte[] data) throws Exception{

		if(data ==null) data = new byte[BUFFER];

		// en afficher le nom
		logger.info("Adding: "+file);

		// création d'un flux de lecture
		FileInputStream fi = new FileInputStream(file);

		// création d'un tampon de lecture sur ce flux
		BufferedInputStream buffi = new BufferedInputStream(fi, BUFFER);

		// création d'en entrée Zip pour ce fichier
		//	            ZipEntry entry = new ZipEntry(file.getName());
		ZipEntry entry = new ZipEntry(StringUtils.supprimeAccents(file.getName()));

		// ajout de cette entrée dans le flux d'écriture de l'archive Zip
		zipOut.putNextEntry(entry);

		// écriture du fichier par paquet de BUFFER octets
		// dans le flux d'écriture
		int count;
		while((count = buffi.read(data, 0, BUFFER)) != -1) {
			zipOut.write(data, 0, count);
		}

		// Close the current entry
		zipOut.closeEntry();

		// fermeture du flux de lecture
		buffi.close();


	}

	/**
	 * Get filename from a complete url
	 * @param urlFileGenerated
	 * @return
	 */
	public static String getFileName(String urlFileGenerated) {

		String result = "";

		if (urlFileGenerated != null) {
			result = urlFileGenerated.substring(urlFileGenerated.lastIndexOf("/") + 1);
		}
		return result;
	}






	public static int getNbFileLines(String urlFileGenerated) throws IOException {

		File fileGenerated = new File(urlFileGenerated);
		BufferedReader fileGeneratedContent = new BufferedReader(new FileReader(fileGenerated));

		int nbLines = 0;
		while (fileGeneratedContent.ready()) {
			fileGeneratedContent.readLine();
			nbLines ++;
		}

		return nbLines;
	}

	public static void copyBinaryFile(InputStream source, String destination) throws TechnicalException {
		try {
			FileOutputStream fout = new FileOutputStream(destination);
			byte[] b = new byte[1024];
			int noOfBytes = 0;
			while((noOfBytes = source.read(b)) != -1) {
				fout.write(b, 0, noOfBytes);
			}
			source.close();
			fout.close();
		} catch(FileNotFoundException e) {
			throw new TechnicalException(e.getMessage(), e);
		} catch(IOException e) {
			throw new TechnicalException(e.getMessage(), e);
		}
	}

	public static void copyBinaryFile(File source, File destination) throws TechnicalException {
		try {
			FileUtils.copyFile(source, destination);
		} catch(FileNotFoundException e) {
			throw new TechnicalException(e.getMessage(), e);
		} catch(IOException e) {
			throw new TechnicalException(e.getMessage(), e);
		}
	}

	/**
	 * Creates files in the given "filePath" parameter if
	 * they do not already exist.
	 * @param existingPath (can be null)
	 * @param filePath (files separated by '\' or '/')
	 * @return boolean : indicates if files were created or not
	 */
	public static boolean mkdirs(String existingPath, String dirPath){
		if(dirPath == null || dirPath.trim().equals("")) return false;
		String[] dirs = null;
		if(existingPath == null) existingPath = "";
		if(dirPath.indexOf("\\") != -1){
			dirs = dirPath.split("\\\\+");
		}else if (dirPath.indexOf("/") != -1){
			dirs = dirPath.split("/+");
		}
		for (int i = 0; i < dirs.length; i++) {
			if(dirs[i] == null || dirs[i].trim().equals("")) continue;
			File f = new File(existingPath + "\\" + dirs[i]);
			if(!f.exists())
				f.mkdirs();
			existingPath += "\\" + dirs[i];
		}
		return true;
	}



	/**
	 * Get filedirectory from a complete url
	 * @param urlFileGenerated
	 * @return
	 */
	public static String getFileDirectory(String urlFileGenerated) {

		String result = "";

		if (urlFileGenerated != null) {
			result = urlFileGenerated.substring(0, urlFileGenerated.lastIndexOf("/") + 1);
		}

		return result;

	}





	public static byte[] getBytesFromFileOldMethode(File file) throws IOException {
		InputStream is = new FileInputStream(file);
		// Get the size of the file
		long length = file.length();

		if (length > Integer.MAX_VALUE) {
			// File is too large
		}

		// Create the byte array to hold the data
		byte[] bytes = new byte[(int)length];

		// Read in the bytes
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length
				&& (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
			offset += numRead;
		}

		// Ensure all the bytes have been read in
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file "+file.getName());
		}

		// Close the input stream and return bytes
		is.close();
		return bytes;
	}

	public static byte[] getBytesFromFile(File file) throws IOException {  
		return ByteUtils.getBytesFromStream(new FileInputStream(file));
	}

	public static File writeInTextFile(File file,String inStr, boolean append) throws IOException {

		PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(file,append))); 
		pw.print(inStr);
		pw.close();
		return file;

	}

	public static void writeBytesInFile(String filepath, byte[] bytes)throws IOException {	    	
		writeBytesInFile(new File(filepath), bytes);
	}
	public static void writeBytesInFile(File file, byte[] bytes)throws IOException {

		OutputStream os = new FileOutputStream(file);
		os = ByteUtils.writeBytesInFlux(os, bytes);
		os.close();


	}

	public static void main(String[] args) {
		try{
			FilesUtilsImpl f = new FilesUtilsImpl();
			//			System.out.println("isAFileInDirectory " + f.isAFileInDirectory("bja.txt", "D:/tmp/bja"));

			//			boolean b = f.copyFile2Directory("D:/tmp/bja/bja.txt", "D:/tmp/bja");
			//			System.out.println("b "+b);
			//			boolean b = f.copyFile2Directory("bja.txt","D:/tmp/bja", "D:/tmp/bja", "bja3.txt");
			//			System.out.println("b "+b);

			//System.out.println("delete "+(f.deleteFile("bja3.txt", "D:/tmp/bja")));

			//			System.out.println("deleteall "+(f.deleteAllFile("D:/tmp/bja/dd")));

			//			System.out.println("nbFichier "+(f.countFile("D:/tmp/bja")));

		}catch (Exception e) {
			e.printStackTrace();
		}
	}


	/**
	 * verification de la presence d'un repertoire ou d'un fichier
	 * @param path
	 * @throws IOException si le repertoire n'existe pas
	 */
	public boolean verifyFileOrDirectory(String path, boolean showErrors) throws IOException{
		File directory = new File(path);
		if(!directory.canRead()){
			if(showErrors) throw new IOException(REPERTOIRE_NON_VISIBLE);

			return false;
		}

		return true;

	}

	/**
	 * @see IFileUtils#isAFileInDirectory(String, String)
	 */
	public boolean isAFileInDirectory(String filename, String filePathName)
	throws IOException {
		verifyFileOrDirectory(filePathName,true);
		return (new File(filePathName, filename)).canRead();
	}


	/**
	 * @see IFileUtils#copyFile2Directory(String, String)
	 */
	public boolean copyFile2Directory(String source,String destinationDirectory) throws IOException {
		verifyFileOrDirectory(destinationDirectory,true);
		FileUtils.copyFileToDirectory(new File(source), new File(destinationDirectory)) ;

		return verifyFileOrDirectory(destinationDirectory+File.separator+new File(source).getName(),false);

	}

	/**
	 * @see IFileUtils#copyFile2Directory(String, String, String, String)
	 */
	public boolean copyFile2Directory(String fileName,String pathOriginePath, String pathDestPath, String fileNameDest)
	throws IOException {

		verifyFileOrDirectory(pathDestPath,true);

		File source = new File(pathOriginePath+File.separator+fileName );
		File destination = new File(pathDestPath+File.separator+fileNameDest );

		org.apache.commons.io.FileUtils.copyFile(source, destination) ;
		return verifyFileOrDirectory(destination.getAbsolutePath(),false);
	}


	/**
	 * @see IFileUtils#deleteFile(String, String)
	 */
	private boolean deleteFile(File file) throws IOException{
		file.delete();

		return !verifyFileOrDirectory(file.getAbsolutePath() ,false);

	}

	/**
	 * @see IFileUtils#deleteFile(String, String)
	 */
	public boolean deleteFile(String fileName, String directory) throws IOException {

		verifyFileOrDirectory(directory,true);
		String absolutePath = directory+File.separator+fileName;
		return deleteFile(new File(absolutePath));


	}

	/**
	 * @see IFileUtils#deleteAllFile(String)
	 */
	public boolean deleteAllFile(String directory) throws IOException {

		verifyFileOrDirectory(directory,true);
		File fileDirectory = new File(directory);
		boolean result = true;
		for(File file:fileDirectory.listFiles()){
			result &= deleteFile(file);
		}
		return result;
	}

	/**
	 * @see IFileUtils#countFileRep(String)
	 */
	public int countFileRep(String directory) throws IOException {
		verifyFileOrDirectory(directory,true);

		return new File(directory).list().length;		
	}

	/**
	 * @see IFileUtils#countFile(String)
	 */
	public int countFile(String directory) throws IOException {
		verifyFileOrDirectory(directory,true);
		File[] listFile = new File(directory).listFiles();

		int nbFiles = 0; 
		for(File file : listFile){
			if(file.isFile()) nbFiles++;
		}

		return nbFiles;		
	}

}
