package com.bja.bapps.tools.core.test;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.junit.Before;
import org.junit.Test;

import com.bja.bapps.tools.core.Book;
import com.bja.bapps.tools.core.BookStore2;
import com.bja.bapps.tools.core.jaxb.JaxBUtils;


public class TestBookStore2 {


	private static final String BOOKSTORE_XML = "h:/bookstore-jaxb.xml";
	// create JAXB context and instantiate marshaller
    JAXBContext context = null;
	
	@Before
	public void init(){
		try {
			context = JAXBContext.newInstance(BookStore2.class);
		} catch (JAXBException e) {			
			e.printStackTrace();
		}
		System.out.println("bja");
	}
	
	@Test
	public void testWriteFile() throws JAXBException, IOException {

		ArrayList<Book> bookList = new ArrayList<Book>();

		// create books
		Book book1 = new Book();
		book1.setIsbn("978-0060554736");
		book1.setName("The Game");
		book1.setAuthor("Neil Strauss");
		book1.setPublisher("Harpercollins");
		bookList.add(book1);

		Book book2 = new Book();
		book2.setIsbn("978-3832180577");
		book2.setName("Feuchtgebiete");
		book2.setAuthor("Charlotte Roche");
		book2.setPublisher("Dumont Buchverlag");
		bookList.add(book2);

		// create bookstore, assigning book
		BookStore2 bookstore = new BookStore2();
		bookstore.setName("Fraport Bookstore");
		bookstore.setLocation("Frankfurt Airport");
		bookstore.setBookList(bookList);

		
		Marshaller m = context.createMarshaller();
		m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

		// Write to System.out
		m.marshal(bookstore, System.out);

		// Write to File
		m.marshal(bookstore, new File(BOOKSTORE_XML));
	}

	@Test
	public void testReadFile() throws JAXBException, IOException {
		
		System.out.println("Output from our XML File: ");
		
		BookStore2 bookstore2 =JaxBUtils.parse(BOOKSTORE_XML, BookStore2.class, context);

		ArrayList<Book> list = bookstore2.getBooksList();
		for (Book book : list) {
			System.out.println("Book: " + book.getName() + " from "
					+ book.getAuthor());
		}
		
	}

	
	
	

		

	
}







