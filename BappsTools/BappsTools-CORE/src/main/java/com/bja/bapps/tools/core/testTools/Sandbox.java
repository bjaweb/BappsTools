package com.bja.bapps.tools.core.testTools;

import java.io.File;
import java.io.IOException;

public class Sandbox {

	public static final String SANDBOX_DIRECTORY_PATH = "src/test/sandbox";

	private static File sandBoxDirectory = new File(SANDBOX_DIRECTORY_PATH);

	public Sandbox() {
	}

	public static void create() {
		sandBoxDirectory.mkdir();
	}

	public static boolean delete() {
		return deleteDir(sandBoxDirectory);
	}

	private static boolean deleteDir(File directory) {
		if (directory.isDirectory()) {
			for (String file : directory.list()) {
				boolean success = deleteDir(new File(directory, file));
				if (!success) {
					return false;
				}
			}
		}
		return directory.delete(); 
	}

	public static String getSandBoxPath() throws IOException {
		return sandBoxDirectory.getCanonicalPath();
	}

}
