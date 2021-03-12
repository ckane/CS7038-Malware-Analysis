/*
 * Hello Script
 *
 */
// @category CS6038.Demo
import java.io.*;
import java.util.*;

import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.app.script.GhidraScript;

public class HelloScript extends GhidraScript {
  public void run() throws Exception {
    println("Hello I am a Java Script");
  }
}
