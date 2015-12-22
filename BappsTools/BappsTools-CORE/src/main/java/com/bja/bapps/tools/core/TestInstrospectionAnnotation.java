package com.bja.bapps.tools.core;
 
import java.lang.reflect.Method;

import com.bja.bapps.tools.core.Todo.Importance;
 
 
@Todo(importance = Importance.CRITIQUE, 
      description = "Corriger le bug dans le calcul", 
      assigneA = "JMD", 
      dateAssignation = "11-11-2007")
public class TestInstrospectionAnnotation {
 
  @SuppressWarnings("unchecked")
public static void main(
      String[] args) {
    Todo todo = null;
 
    // traitement annotation sur la classe
    Class classe = TestInstrospectionAnnotation.class;
    todo = (Todo) classe.getAnnotation(Todo.class);
    if (todo != null) {
      System.out.println("classe "+classe.getName());
      System.out.println("  ["+todo.importance()+"]"+" ("+todo.assigneA()
	    +" le "+todo.dateAssignation()+")");
      for(String desc : todo.description()) {
        System.out.println("     _ "+desc);
      }
    }
    
    // traitement annotation sur les méthodes de la classe    
    for(Method m : TestInstrospectionAnnotation.class.getMethods()) {
      todo = (Todo) m.getAnnotation(Todo.class);
      if (todo != null) {
        System.out.println("methode "+m.getName());
        System.out.println("  ["+todo.importance()+"]"+" ("+todo.assigneA()
		  +" le "+todo.dateAssignation()+")");
        for(String desc : todo.description()) {
          System.out.println("     _ "+desc);
        }
      }
    }
  }
 
  @Todo(importance = Importance.MAJEUR, 
        description = "Implementer la methode", 
        assigneA = "JMD", 
        dateAssignation = "11-11-2007")
  public void methode1() {
    
  }
  
  @Todo(importance = Importance.MINEURE, 
        description = {"Completer la methode", "Ameliorer les logs"}, 
        assigneA = "JMD", 
        dateAssignation = "12-11-2007")
  public void methode2() {
    
  }
 
}