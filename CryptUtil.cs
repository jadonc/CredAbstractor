/* Author:	Jadon Combs
   Date:	21 April 2020
   Team:	VAA
   Title:	Encryptor and decryptor utility
   
   
   README:
   -------
   This "program" or "component" encrypts and decrypts a file
   containing data essential to connecting to a database used
   and frequented by the parent application.
   
   To ensure the proper mode ("encrypt" or "decrypt") is used,
   the following strategy is adopted:
   
		1. b = LAST N bytes of <keyPath> (see below).
		2. IF ( b == <code data>):
			- <credPath> IS ALREADY ENCRYPTED.
			- DELETE the last N bytes from <keyPath>
			- DECRYPT <credPath> via <keyPath>
		3. ELSE:
			- <credPath> IS NOT ENCRYPTED (PLAINTEXT).
			- ENCRYPT <credPath> via <keyPath>
			- ADD <code data> (N bytes) to end of <keyPath>
			
			
	REGARDING DETAILS ON INTEGRATION:
	---------------------------------
	(instructions copied from Driver file)
	1. Include the <CryptUtilNS> namespace in your project.
    2. Create an instance of CryptUtil with the <config> (1 param)
	   constructor, or the two-file constructor (two params).
	   If you need to, use one of the public-facing methods
	   listed below to set the appropriate cred- and key- files.
	
	3. PUBLIC INTERFACING INSTANCE METHODS ARE LISTED BELOW:
	
	     your_instance.runCryptUtil():
				- retrieve plaintext credentials from encrypted file
		
		 your_instance.setCredAndKeyFiles(cred_fpath, key_fpath):
				- set which file holds credentials, and which holds the key
				
		 your_instance.setConfig(config_fpath):
			    - credfile and keyfile will be created based on this
				- (see private initConfig(...) method for more details)
			
   
   For more specific information, please contact the author or
   relevant person(s).
*/ 


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace CryptUtilNS { // "NS" = "namespace"

	public class CryptUtil {
		/* ATTRIBUTES HERE:
		   ----------------
		   credPath:	The file here contains the essential data
						previously mentioned.
						
		   keyPath:		The file here contains a string used in
						encrypting/decrypting credPath.
						
		   code:		Value that indicates whether a file is
					    encrypted or not.
							
						
		   ASSUMPTION(S):
		   --------------
		   > File paths are based on current working directory
		     unless it is specified otherwise.
		*/
		
		public string credPath { get; set; }	// File path for essential data
		public string keyPath { get; set; }		// File path for key
		private string code = "509AfGd3Yux";	// Used to indicate if file encrypted
		
		
		// Constructor -- Default
		public CryptUtil() { }
		
		
		// Constructor -- initialize with a file ADHERING TO THE FOLLOWING FORMAT:
		// LINE 1: ALL "essential data" information
		// LINE 2: key used to encrypt and decrypt
		public CryptUtil( string configFile ) {
			if (!File.Exists(configFile)) return;
			initConfig(configFile); // Create & init <credPath> & <keyPath> files
		}
		
		
		// Constructor -- initialize with a credential file, and key file
		public CryptUtil( string credFpath, string keyFpath ) {
			if (!File.Exists(credFpath) || !File.Exists(keyFpath)) return;
			
			credPath = credFpath;
			keyPath = keyFpath;
		}
		
		
		// Helper method: init <credPath> and <keyPath> based on configPath
		private bool initConfig(string configPath) {
			string data;
			
			// Create separate file to hold essential data
			using (StreamWriter writer = new StreamWriter("cred_data.txt")) {
				data = File.ReadLines(configPath).ElementAtOrDefault(0);
				credPath = "cred_data.txt";
				writer.WriteLine(data);
			}
			
			// Create separate file to hold key
			using (StreamWriter writer = new StreamWriter("key_data.txt")) {
				data = File.ReadLines(configPath).ElementAtOrDefault(1);
				keyPath = "key_data.txt";
				writer.WriteLine(data);
			}
			
			return true;
		}
		
		
		// Helper method: get key value (used to encrypt/decrypt);
		// Ensure <keyPath> is correct file path, and that
		// key is in first line of file.
		// Return: plaintext string
		private string getKey() {
			return File.ReadLines(keyPath).First();
		}
		
		
		// Helper method: return "essential data" that will
		//				  be directly returned to requester class
		// Assumption(s): <credPath> is already decrypted;
		//				  all "essential" info on 1st line of <credPath>
		// Return: the data in <credPath>
		private string getCredStr() {
			string data = File.ReadLines(credPath).First();
			return data;
		}
		
		
		// Helper method: add value of <code> to end of <keyPath> data
		// Return: true if successful
		private bool setEncrypted(string fpath) {
			byte[] b = str2bytes(code);
			using (var fs = new FileStream(fpath, FileMode.Append)) {
				fs.Write(b, 0, b.Length);
				return true;
			}
		}
		
		
		// Helper method: create file if it doesn't exist;
		private void checkFile(string fpath) {
			using (StreamWriter sw = File.AppendText(fpath)) { ; }
		}
		
		
		// Helper method: convert bytes to string;
		// Assumption(s): Encoding is UTF8
		// Return: string
		private string bytes2str( byte[] b ) {
			return Encoding.UTF8.GetString(b);
		}
		
		
		// Helper method: convert string to bytes;
		// Assumption(s): Encoding is same as used in "bytes2str()"
		// Return: byte[]
		private byte[] str2bytes( string s ) {
			return Encoding.UTF8.GetBytes(s);
		}
		
		
		// Helper method: read last N bytes of a file <fpath>
		// Return: byte[]
		private byte[] readLastNBytes(int N, string fpath) {
			byte[] data = new byte[N];
			
			// READ the last N bytes from <fpath>; "rdr" is "reader"
			using (var rdr = new StreamReader(keyPath)) {
				
				if (rdr.BaseStream.Length  > N) {
					rdr.BaseStream.Seek(-N, SeekOrigin.End);
				}
				rdr.BaseStream.Read(data, 0, N);
			}
			
			return data;
		}
		
		
		// Helper method: delete last N bytes of a file <fpath>
		private void delLastNBytes(int N, string fpath) {
			FileInfo finfo = new FileInfo(fpath);
			FileStream fs = finfo.Open(FileMode.Open);
			fs.SetLength( Math.Max(0, finfo.Length-N) ); // Decrease length
			fs.Close();
		}
		
		
		// Helper method: check last N bytes of <keyPath>;
		// Return: <true> if last N bytes == <code>
		private bool encrypted() {
			byte[] b = readLastNBytes(code.Length, keyPath);
			string s = bytes2str(b);
			return s.Equals(code);
		}
		
		
		// Decryption method
		private void decryptFile(string fpath, string key) {
			
			// Clear the <code> data in <keyPath> before starting decryption process
			delLastNBytes(code.Length, keyPath);
			key = getKey();
			
			// Read in encrypted data
			byte[] encrypted = File.ReadAllBytes(fpath);
			
			// ERROR CHECKS
			if (string.IsNullOrEmpty(key))
				throw new ArgumentNullException("key");
			if (encrypted.Length <= 0)
				throw new ArgumentNullException("fpath");
			
			
			
			using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider()) {
				
				// Generate salt, key
				byte[] salt = Encoding.UTF8.GetBytes("sALtysPitoOn");
				Rfc2898DeriveBytes aesKey = new Rfc2898DeriveBytes(key, salt);
				
				aes.KeySize = 128;
				aes.Key = aesKey.GetBytes(aes.KeySize / 8);
				aes.IV = aesKey.GetBytes(aes.BlockSize / 8);
				
				// Create streams for decryption
				using (MemoryStream msd = new MemoryStream()) {
					
					using (CryptoStream csd = new CryptoStream(msd,
						aes.CreateDecryptor(), CryptoStreamMode.Write)) {
						
						// Write decrypted data back to file
						csd.Write(encrypted, 0, encrypted.Length);
					}
					
					byte[] output = msd.ToArray();
					File.WriteAllBytes(fpath, output);
						
					// Diagnostic/confirmation
					Console.WriteLine("["+fpath+"] decryption successful.");
				}
			}
		}
		
		
		// Encryption method
		private void encryptFile(string fpath, string key) {
			
			// Check if file already encrypted
			if ( encrypted() ) return;
			
			// Read in plaintext data
			byte[] decrypted = File.ReadAllBytes(fpath);
			
			// ERROR CHECKS
			if (string.IsNullOrEmpty(key))
				throw new ArgumentNullException("key");
			if (decrypted.Length <= 0)
				throw new ArgumentNullException("fpath");
			
			
			
			using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider()) {
				
				// Create salt, use RFC2898 to hash
				byte[] salt = Encoding.UTF8.GetBytes("sALtysPitoOn");
				Rfc2898DeriveBytes aesKey = new Rfc2898DeriveBytes(key, salt);
				
				aes.KeySize = 128;
				aes.Key = aesKey.GetBytes(aes.KeySize / 8);
				aes.IV = aesKey.GetBytes(aes.BlockSize / 8);
				
				// Create streams for encryption
				using (MemoryStream mse = new MemoryStream()) {
					
					using (CryptoStream cse = new CryptoStream(mse,
						aes.CreateEncryptor(), CryptoStreamMode.Write)) {
						
						// Write encrypted data back to file
						cse.Write(decrypted, 0, decrypted.Length);
					}
					
					byte[] output = mse.ToArray();
					File.WriteAllBytes(fpath, output);
					
					// Diagnostic/confirmation
					Console.WriteLine("["+fpath+"] encryption successful.");
				}
			}
			
			// Add string in <code> to end of <keyPath> data
			setEncrypted(keyPath);	
		}
		
		
		// PUBLIC method: set <credPath> and <keyPath> at once;
		// Not seperating because potential security risk;
		public void setCredAndKeyFiles(string credFpath, string keyFpath) {
			credPath = credFpath;
			keyPath = keyFpath;
			checkFile(credPath); 	// Create file if it doesn't exist
			checkFile(keyPath);		// Create file if it doesn't exist
		}
		
		
		// PUBLIC method: set <credPath> & <keyPath> based on configPath
		public bool setConfig(string configPath) {
			if (!File.Exists(configPath)) return false;
			return initConfig(configPath); // Use private helper method
		}
		
		
		/* ========== MAIN INTERFACING METHOD =========== */
		// This will automatically DECRYPT <credPath> if
		// <keyPath> data ends with the <code> specified
		// at beginning of CryptUtil.cs. If <code> is NOT
		// present at end of <keyPath> data, <credPath>
		// will automatically be ENCRYPTED.
		public string runCryptUtil() {
			string s = "<ENCRYPTED>"; 					// Default value
			string k = getKey();						// Key container
			
			// Abort if <credPath> and <keyPath> files do not exist
			if ( !File.Exists(credPath) || !File.Exists(keyPath) ) {
				Console.WriteLine( "CRYPT_UTIL_FILE_ERR:\n" +
					"Keyfile or Credentialfile can't be found");
				return s;
			}
			
			// Abort if key file is empty
			if ( string.IsNullOrEmpty(k) ) {
				Console.WriteLine( "CRYPT_UTIL_KEY_ERR:\n" +
					"Keyfile '{0}' is empty.");
				return s;
			}
			
			// Check if essential data is encrypted
			if ( encrypted() ) {
				decryptFile(credPath, k);		// Decrypt file
				s = getCredStr();				// Get essential data
				k = getKey();
				encryptFile(credPath, k);		// Encrypt file
			}
			
			// Essential data is NOT encrypted
			else {
				s = getCredStr();				// Get essential data
				encryptFile(credPath, k);		// Encrypt file
			}
			
			return s;							// Return <s> to client
		}
	}

}