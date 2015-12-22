package com.bja.bapps.tools.core.utils.dataType;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ByteUtils {
	
	public static byte[] getBytesFromStream(InputStream is) throws IOException {
        
    	DataInputStream dIn = new DataInputStream(is);
		byte bytes[]=new byte[dIn.available()];
		dIn.readFully(bytes);
    	is.close();
    	dIn.close();
    	return bytes;
    }
	

	public static OutputStream writeBytesInFlux(OutputStream os,byte[] bytes) throws IOException {
        
		os.write(bytes);
		os.flush();		
		return os;
    }

	

}
