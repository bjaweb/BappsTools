package com.bja.bapps.tools.core.test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.junit.Test;

import com.bja.bapps.tools.core.BD;
import com.bja.bapps.tools.core.Book;
import com.bja.bapps.tools.core.Bookstore;
import com.bja.bapps.tools.core.jaxb.JaxBUtils;

public class TestBookStore {


	private static final String BOOKSTORE_XML = "h:/bookstore-jaxb2.xml";
	private static final String BJA_XML = "h:/bja.xml";

	@Test
	public void testJB2() throws JAXBException, IOException {

		Bookstore bjaStore = JaxBUtils.parse(BJA_XML, Bookstore.class);
		System.out.println(bjaStore);
	}
	
	@Test
	public void testReadFile() throws JAXBException, IOException {
		
		System.out.println("Output from our XML File: ");
		Unmarshaller um = JAXBContext.newInstance(Bookstore.class).createUnmarshaller();
		Bookstore bookstore2 = (Bookstore) um.unmarshal(new FileReader(BOOKSTORE_XML));
		
		for (Book book :  bookstore2.getBooks()) {
			System.out.println("Book: " + book.getName() + " from "
					+ book.getAuthor());
		}
		
		for (BD book :  bookstore2.getBds()) {
			System.out.println("bd: " + book.getName() + " de "+ book.getAuthor() + " zzc "+book.isZzc() + " pour:"+book.getPublicVise());
		}
		
	}

	
	@Test
	public void testJB3() throws JAXBException, IOException {

		Bookstore bjaStore = new Bookstore();
		bjaStore.setLocation("Verbeno");
		bjaStore.setName("magasin de ben");
		
		
		Book book1 = new Book();
		book1.setIsbn("9aaaaa");
		book1.setName("The Game1");
		book1.setAuthor("Neil Strauss");
		book1.setPublisher("Harpercollins"); 

		Book book2 = new Book();
		book2.setIsbn("978-383218057a7");
		book2.setName("BBBBQ");
		book2.setAuthor("Charlotte Roche");
		book2.setPublisher("Dumont Buchverlag");
		
		BD bd1 = new BD();
		bd1.setIsbn("111");
		bd1.setName("La bd de test");
		bd1.setAuthor("Benleben");
		bd1.setPublisher("Hachette");
		bd1.setPublicVise("gosse");
		bd1.setZzc(true);
		
		
		List<Book> books = new ArrayList<Book>();
		books.add(book1);books.add(book2);
 		
		List<BD> bds = new ArrayList<BD>();
		bds.add(bd1);
		
		bjaStore.setBooks(books);
		bjaStore.setBds(bds);
		
		System.out.println(bjaStore);
		
		
		// create JAXB context and instantiate marshaller
		JAXBContext context = JAXBContext.newInstance(Bookstore.class);
		Marshaller m = context.createMarshaller();
		m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
//
//		// Write to System.out
		m.marshal(bjaStore, System.out);
		
		m.marshal(bjaStore, new File(BOOKSTORE_XML));
	}

	
	
	
	
	
}


