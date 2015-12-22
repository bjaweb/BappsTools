package com.bja.bapps.tools.core.utils.files;

import java.io.IOException;

public interface IFileUtils {



	public static String REPERTOIRE_NON_VISIBLE = "Repertoire invisible";
	public static final int BUFFER = 2048;

	/**
	 * test si un fichier est dans le repertoire passé en parametre
	 * 
	 * @param filename
	 * @param filePathName
	 * @return true si fichier present, false sinon
	 * @throws Exception : quand le repertoire n'existe pas
	 */
	public boolean isAFileInDirectory(String filename, String filePathName) throws IOException;


	/**
	 * 
	 * copie un fichier dans un repertoire
	 * 
	 * @param source
	 * @param destination : chemin absolu vers le repertoire de destination
	 * @return quand le AbsoluteDirectoryPath n'existe pas
	 * @throws IOException quand la source est la destiniation n'existe pas
	 */
	public boolean copyFile2Directory(String source, String destination) throws IOException;

	/**
	 * copie un fichier dans un repertoire
	 * @param fileName
	 * @param pathOriginePath
	 * @param pathDestPath
	 * @param fileNameDest
	 * @return 
	 * @throws Exception quand le pathDestPath n'existe pas, quand la source n'existe pas
	 */
	public boolean copyFile2Directory(String fileName, String pathOriginePath, String pathDestPath,  String fileNameDest) throws IOException;


	/**
	 * suppression de fichier dans un repertoire
	 * @param fileName
	 * @param directory
	 * @return
	 * @throws Exception quand le directory n'existe pas
	 */
	public boolean deleteFile(String fileName, String directory) throws IOException;


	/**
	 * suppression de tout les fichiers d'un repertoire
	 * @param directory
	 * @return
	 * @throws Exception
	 */
	public boolean deleteAllFile(String directory) throws IOException;


	/**
	 * nombres de fichiers dans un repertoire
	 * @param directory
	 * @return
	 * @throws Exception
	 */
	public int countFile(String directory) throws IOException;

	/**
	 * nombres de fichiers et repertoires dans un repertoire
	 * @param directory
	 * @return
	 * @throws Exception
	 */
	public int countFileRep(String directory) throws IOException ;


}
