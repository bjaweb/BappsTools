package com.bja.bapps.tools.security;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;



// plus utilisée
public class GnuPG {
	
	private String kGnuPGCommand;

	// Class vars:
	private File	tmpFile;
	private int		gpg_exitCode = -1;
	private String	gpg_result;
	private String	gpg_err;
	
	public GnuPG(String homedir) throws SecurityException{
		System.out.println("chemin "+homedir+"/gpg");
		this.kGnuPGCommand = homedir+"/gpg --homedir "+homedir;
		File file = new File(homedir+"/gpg.exe");
		if(!file.canRead()) throw new SecurityException("gpg not found");
	}

	/**
	 * Reads an output stream from an external process.
	 * Imeplemented as a thred.
	 */
	class ProcessStreamReader
	extends Thread
	{
		StringBuffer		stream;
		InputStreamReader	in;

		final static int BUFFER_SIZE = 1024;

		/**
		 *	Creates new ProcessStreamReader object.
		 *	
		 *	@param	in
		 */
		ProcessStreamReader (InputStream in)
		{
			super();

			this.in = new InputStreamReader(in);

			this.stream = new StringBuffer();
		}

		public void run()
		{
			try
			{       
				int read;
				char[] c = new char[BUFFER_SIZE];

				while ((read = in.read(c, 0, BUFFER_SIZE - 1)) > 0)
				{
					stream.append(c, 0, read);
					if (read < BUFFER_SIZE - 1) break;
				}
			}
			catch(IOException io) {}
		}

		String getString()
		{
			return stream.toString();
		}
	}


	/**
	 * Sign
	 *
	 * @param	inStr		input string to sign
	 * @param	passPhrase	passphrase for the personal private key to sign with
	 * @return				true upon success
	 */
	public boolean sign (String inStr, String passPhrase)
	{
		boolean		success;

		success = createTempFile (inStr);

		if (success)
		{
			success = runGnuPG ("--passphrase-fd 0 --sign " + this.tmpFile.getAbsolutePath (), passPhrase);
			this.tmpFile.delete ();
			if (success && this.gpg_exitCode != 0)
				success = false;
		}
		return success;
	}


	/**
	 * ClearSign
	 *
	 * @param	inStr		input string to sign
	 * @param	passPhrase	passphrase for the personal private key to sign with
	 * @return				true upon success
	 */
	public boolean clearSign (String inStr, String passPhrase)
	{
		boolean		success;

		success = createTempFile (inStr);

		if (success)
		{
			success = runGnuPG ("--passphrase-fd 0 --clearsign " + this.tmpFile.getAbsolutePath (), passPhrase);
			this.tmpFile.delete ();
			if (success && this.gpg_exitCode != 0)
				success = false;
		}
		return success;
	}


	/**
	 * Signs and encrypts a string
	 *
	 * @param	inStr		input string to encrypt
	 * @param	keyID		key ID of the key in GnuPG's key database to encrypt with
	 * @param	passPhrase	passphrase for the personal private key to sign with
	 * @return				true upon success
	 */
	public boolean signAndEncrypt (String inStr, String keyID, String passPhrase)
	{
		boolean		success;

		success = createTempFile (inStr);

		if (success)
		{
			success = runGnuPG ("--passphrase-fd 0 -se " + this.tmpFile.getAbsolutePath (), passPhrase);
			this.tmpFile.delete ();
			if (success && this.gpg_exitCode != 0)
				success = false;
		}
		return success;
	}


	/**
	 * Encrypt
	 *
	 * @param	filePath	chemin du fichier à crypter
	 * @param	keyID		key ID of the key in GnuPG's key database to encrypt with
	 * @return				true upon success
	 */
	public boolean encrypt (String filePath, String keyID)
	{
		boolean		success;

		success = runGnuPG ("-e -r "+keyID+" " +filePath);
		if (success && this.gpg_exitCode != 0)
			success = false;
		return success;
	}



	/**
	 * Decrypt
	 *
	 * @param	inStr		input string to decrypt
	 * @param	passPhrase	passphrase for the personal private key to sign with
	 * @return				true upon success
	 */
	public boolean decrypt (String inStr, String passPhrase)
	{
		boolean		success;

		success = createTempFile (inStr);

		if (success)
		{
			success = runGnuPG ("--passphrase-fd 0 --decrypt " + this.tmpFile.getAbsolutePath (), passPhrase);
			this.tmpFile.delete ();
			if (success && this.gpg_exitCode != 0)
				success = false;
		}
		return success;
	}


	/**
	 * Verify a signature
	 *
	 * @param	inStr	signature to verify
	 * @param	keyID	key ID of the key in GnuPG's key database
	 * @return			true if verified.
	 */
	/*
	public boolean verifySignature (String inStr, String keyID)
	{
		boolean		success;

		success = runGnuPG ("--sign " + keyID, inStr);
		if (success && this.gpg_exitCode != 0)
			success = false;
		return success;
	}
	 */

	/**
	 * Get processing result
	 *
	 * @return			result string.
	 */
	public String getResult ()
	{
		return gpg_result;
	}


	/**
	 * Get error output from GnuPG process
	 *
	 * @return			error string.
	 */
	public String getErrorString ()
	{
		return gpg_err;
	}


	/**
	 * Get GnuPG exit code
	 *
	 * @return			exit code.
	 */
	public int getExitCode ()
	{
		return gpg_exitCode;
	}


	/**
	 * Runs GnuPG external program
	 *
	 * @param	commandArgs	command line arguments
	 * @param	inputStr	key ID of the key in GnuPG's key database
	 * @return				true if success.
	 */
	private boolean runGnuPG (String commandArgs, String inputStr)
	{
		Process		p;
		String		fullCommand = kGnuPGCommand + " " + commandArgs;

		System.out.println (fullCommand);

		try
		{
			p = Runtime.getRuntime().exec(fullCommand);
		}
		catch(IOException io)
		{
			System.out.println ("io Error" + io.getMessage ());
			return false;
		}

		ProcessStreamReader psr_stdout = new ProcessStreamReader(p.getInputStream());
		ProcessStreamReader psr_stderr = new ProcessStreamReader(p.getErrorStream());
		psr_stdout.start();
		psr_stderr.start();
		if (inputStr != null)
		{
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(p.getOutputStream()));
			try
			{
				out.write(inputStr);
				out.close();
			}
			catch(IOException io)
			{
				System.out.println("Exception at write! " + io.getMessage ());
				return false;
			}
		}

		try
		{
			p.waitFor();

			psr_stdout.join();
			psr_stderr.join();
		}
		catch(InterruptedException i)
		{
			System.out.println("Exception at waitfor! " + i.getMessage ());
			return false;
		}

		try
		{
			gpg_exitCode = p.exitValue ();
		}
		catch (IllegalThreadStateException itse)
		{
			return false;
		}

		gpg_result = psr_stdout.getString();
		gpg_err = psr_stdout.getString();

		return true;
	}

	
	/**
	 * Runs GnuPG external program
	 *
	 * @param	commandArgs	command line arguments
	 * @param	inputStr	key ID of the key in GnuPG's key database
	 * @return				true if success.
	 */
	private boolean runGnuPG (String commandArgs)
	{
		Process		p;
		String		fullCommand = kGnuPGCommand + " " + commandArgs;
		
		System.out.println (fullCommand);

		try
		{
			p = Runtime.getRuntime().exec(fullCommand);
		}
		catch(IOException io)
		{
			System.out.println ("io Error" + io.getMessage ());
			return false;
		}

		ProcessStreamReader psr_stdout = new ProcessStreamReader(p.getInputStream());
		ProcessStreamReader psr_stderr = new ProcessStreamReader(p.getErrorStream());
		psr_stdout.start();
		psr_stderr.start();

		try
		{
			p.waitFor();

			psr_stdout.join();
			psr_stderr.join();
		}
		catch(InterruptedException i)
		{
			System.out.println("Exception at waitfor! " + i.getMessage ());
			return false;
		}

		try
		{
			gpg_exitCode = p.exitValue ();
		}
		catch (IllegalThreadStateException itse)
		{
			return false;
		}

		gpg_result = psr_stdout.getString();
		gpg_err = psr_stdout.getString();

		return true;
	}

	/**
	 * A utility method for creating a unique temporary file when needed by one of
	 * the main methods.<BR>
	 * The file handle is store in tmpFile object var.
	 *
	 * @param	inStr	data to write into the file.
	 * @return			true if success
	 */
	private boolean createTempFile (String inStr)
	{
		this.tmpFile = null;
		FileWriter	fw;

		try
		{
			this.tmpFile = File.createTempFile ("YGnuPG", null);
		}
		catch (Exception e)
		{
			System.out.println("Cannot create temp file " + e.getMessage ());
			return false;
		}

		try
		{
			fw = new FileWriter (this.tmpFile);
			fw.write (inStr);
			fw.flush ();
			fw.close ();
		}
		catch (Exception e)
		{
			// delete our file:
			tmpFile.delete ();

			System.out.println("Cannot write temp file " + e.getMessage ());
			return false;
		}

		return true;
	}

	
    public static void main (String args[])
	{
//        // use this to check:
//        System.out.println("Hello World!");
//        try{
//		GnuPG pgp = new GnuPG ("C:\\Autorite\\bin");
//		pgp.encrypt ("C:/Autorite/temp/p12.zip","expert-line");
//
//		System.out.println("result: " + new String(pgp.gpg_result) + "\n");
//		System.out.println("error: " + pgp.gpg_err + "\n");
//		System.out.println("exit: " + pgp.gpg_exitCode + "\n");
//        }
//        catch (Exception e) {
//			e.printStackTrace();
//		}
    }
	 

}
