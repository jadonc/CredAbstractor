/* Author:	Jadon Combs
   Date:	21 April 2020
   Team:	VAA
   Title:	DRIVER file for CryptUtil.cs
   
   
   README:
   -------
   This will test the functionality of CryptUtil.cs.
   
   
   TESTING/DEMO INSTRUCTIONS:
   ---------------------
   MAKE SURE you have either a "config" file THAT ADHERES TO the following format:
		- [LINE1]: all "essential data" to be passed to client
		- [LINE2]: KEY used to encrypt/decrypt "essential data"
		
   OR you have two files (IN THIS ORDER):
		- File 1: all "essential data" to be passed to client
		- File 2; KEY used to encrypt/decrypt "essential data"
		
   You can either: 
   1. Compile and run driver (the compiled .exe file), OR
   2. a. include the <CryptUtilNS> namespace in your project.
      b. create an instance of CryptUtil with the <config> (1 param)
	     constructor, or the two-file constructor (two params).
	  c. retrieve sensitive "essential data" via this method:
	  
	     your_instance.runCryptUtil()
	  
   
   For more specific information, please contact the author or
   relevant person(s).
*/ 

using CryptUtilNS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace DriverNS { // "NS" = "namespace"

	public class DriverClass {
		
		
		// Test default constructor; manually set file paths
		public static void test01() {
			Console.WriteLine("Begin test01.");
			
			CryptUtil cryptUtil = new CryptUtil();
			
			// Specify <credPath> and <keyPath> here
			cryptUtil.credPath = "test01cred.txt";
			cryptUtil.keyPath = "test01key.txt";
			
			// Writing sample test data for <credPath>
			using (FileStream fs = File.Create(cryptUtil.credPath)) {
				
				// This is returned to client via "runCryptUtil()"
				byte[] credData = new UTF8Encoding(true)
					.GetBytes("SECRET_P4SSW0RD; ID=69420");
				fs.Write(credData, 0, credData.Length);
			}
			
			// Writing sample test data for <keyPath>
			using (FileStream fs = File.Create(cryptUtil.keyPath)) {
				byte[] keyData = new UTF8Encoding(true).GetBytes("ThisIsAKey");
				fs.Write(keyData, 0, keyData.Length);
			}
			
			// Displaying output;
			Console.WriteLine("CALL 1:");
			string s1 = cryptUtil.runCryptUtil();
			Console.WriteLine("\n");
			
			Console.WriteLine("CALL 2:");
			string s2 = cryptUtil.runCryptUtil();
			Console.WriteLine("\n");
			
			Console.WriteLine("CALL 3:");
			string s3 = cryptUtil.runCryptUtil();
			Console.WriteLine("\n");
			
			Console.WriteLine("call 1 result: " + s1);
			Console.WriteLine("call 2 result: " + s2);
			Console.WriteLine("call 3 result: " + s3);
			
			Debug.Assert(s1.Equals(s2));
			Debug.Assert(s2.Equals(s3));
			
			Console.WriteLine("End test01.");
		}
		
		
		// Test <credFile>, <keyFile> constructor;
		public static void test02() {
			Console.WriteLine("Begin test02");
			
			string credPath = "test02cred.config"; 	// Can use any file extension;
			string keyPath = "test02key.config";	// In this case, ".config" works;
			
			// Writing sample test data for <credPath>
			using (FileStream fs = File.Create(credPath)) {
				
				// This is returned to client via "runCryptUtil()"
				byte[] credData = new UTF8Encoding(true)
					.GetBytes("SECRET_P4SSW0RD; ID=69420");
				fs.Write(credData, 0, credData.Length);
			}
			
			// Writing sample test data for <keyPath>
			using (FileStream fs = File.Create(keyPath)) {
				byte[] keyData = new UTF8Encoding(true).GetBytes("ThisIsAKey");
				fs.Write(keyData, 0, keyData.Length);
			}
			
			CryptUtil cryptUtil = new CryptUtil(credPath, keyPath);
			
			// Displaying output;
			Console.WriteLine("CALL 1:");
			string s1 = cryptUtil.runCryptUtil();
			Console.WriteLine("\n");
			
			Console.WriteLine("CALL 2:");
			string s2 = cryptUtil.runCryptUtil();
			Console.WriteLine("\n");
			
			Console.WriteLine("CALL 3:");
			string s3 = cryptUtil.runCryptUtil();
			Console.WriteLine("\n");
			
			Console.WriteLine("call 1 result: " + s1);
			Console.WriteLine("call 2 result: " + s2);
			Console.WriteLine("call 3 result: " + s3);
			
			Debug.Assert(s1.Equals(s2));
			Debug.Assert(s2.Equals(s3));
			
			Console.WriteLine("End test02.");
		}
		
		
		// Test <configFile> constructor;
		public static void test03() {
			// TBD
		}
		
		
		public static void Main() {
			test01();
			test02();
			test03();
		}
	}
}