package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SeiTchiz {

	private static final int MEGABYTE = 1024;
	private static ObjectOutputStream outStream;
	private static ObjectInputStream inStream;

	private static final String CLIENT = "client/";

	public static void main(String[] args) throws Exception {
		String[] AdressEporta = args[0].split(":");
		String trustStore =  CLIENT + args[1];
		String keyStore = CLIENT + args[2];
		String keyStorePassword = args[3];
		String id = args[4]; // ID of the user
		System.setProperty("javax.net.ssl.trustStore", trustStore);
		System.setProperty("javax.net.ssl.keyStore", keyStore);
		System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
		Scanner sc = new Scanner(System.in);
		System.out.println("User ID: " + id);
		String adress = AdressEporta[0];
		int porta = Integer.parseInt(AdressEporta[1]);
		SocketFactory sf = SSLSocketFactory.getDefault();
		try {
			SSLSocket socket = (SSLSocket) sf.createSocket(adress, porta);
			outStream = new ObjectOutputStream(socket.getOutputStream());
			outStream.writeObject(id);

			inStream = new ObjectInputStream(socket.getInputStream());
			long nonce = (long) inStream.readObject();
			boolean registered = (boolean) inStream.readObject();
			Signature signature = Signature.getInstance("MD5withRSA");
			signature.initSign(getPrivateKey(keyStore, keyStorePassword));
			ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			buffer.putLong(nonce);
			signature.update(buffer.array());
			if(registered) {
				outStream.writeObject(signature.sign());
				boolean b = (boolean) inStream.readObject();
				if(b) {
					System.out.println("Authentication was successful");
				} else {
					System.out.println("Authentication  was not successful");
					return;
				}
			} else {
				outStream.writeObject(nonce);
				outStream.writeObject(signature.sign());
				Certificate cert = getCertificate(keyStore, keyStorePassword);
				outStream.writeObject(cert);
				boolean b = (boolean) inStream.readObject();
				if(b) {
					System.out.println("Regist was successful");
				} else {
					System.out.println("Regist was not successful");
					return;
				}
			}
			String line = null;
			do {
				printOptions(); //Prints all the options the user can do
				line = sc.nextLine(); 
				pedido(line, id, keyStore, keyStorePassword); // Process the request
			} while(!line.equals("quit"));

			socket.close();
			sc.close();

		} catch(FileNotFoundException e) {
			System.out.println("Ficheiro nao existe");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Gets private key from a keyStore
	 * @param key keyStore
	 * @param pw keyStorePassword
	 * @return private key
	 * @throws Exception
	 */
	
	private static PrivateKey getPrivateKey(String key, String pw) throws Exception {
		FileInputStream ins = new FileInputStream(key);

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, pw.toCharArray());
		String alias = keyStore.aliases().asIterator().next();

		return (PrivateKey) keyStore.getKey(alias, pw.toCharArray());
	}

	/**
	 * Gets certificate from a keyStore
	 * @param key keyStore
	 * @param pw keyStorePassword
	 * @return certificate
	 * @throws Exception
	 */
	
	private static Certificate getCertificate(String key, String pw) throws Exception {
		FileInputStream ins = new FileInputStream(key);

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, pw.toCharArray());
		String alias = keyStore.aliases().asIterator().next();
		Certificate cert = keyStore.getCertificate(alias);
		return cert;
	}

	/**
	 * Processes the request of the user
	 * @param line String with the method in the first position after a split by spaces
	 * @throws Exception 
	 */

	private static void pedido(String line, String user, String keyStore, String keyStorePassword) throws Exception {
		String[] t = line.split("\\s+");
		//Switch with every request possible
		switch(t[0]) {
		case "f":
		case "follow":
			if(t.length == 2) {
				outStream.writeObject(line);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "u":
		case "unfollow":
			if(t.length == 2) {
				outStream.writeObject(line);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "v":
		case "viewfollowers":
			if(t.length == 1) {
				outStream.writeObject(line);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "p":
		case "post":
			if(t.length == 2) {
				outStream.writeObject(line);
				post(line);
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "w":
		case "wall":
			if(t.length == 2) {
				outStream.writeObject(line);
				wall();
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "l":
		case "like":
			if(t.length == 2) {
				outStream.writeObject(line);
				System.out.println(inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "n":
		case "newgroup":
			if(t.length == 2) {
				outStream.writeObject(line);
				newGroup(keyStore, keyStorePassword);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "a":
		case "addu":
			if(t.length == 3) {
				outStream.writeObject(line);
				newSecretKey(keyStore, keyStorePassword);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "r":
		case "removeu":
			if(t.length == 3) {
				outStream.writeObject(line);
				newSecretKey(keyStore, keyStorePassword);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "g":
		case "ginfo":
			if(t.length <= 2){
				outStream.writeObject(line);
				System.out.println((String) inStream.readObject());
			}else{
				System.out.println("Executou mal o metodo");
			}
			break;
		case "m":
		case "msg":
			if(t.length >= 3) {
				byte[] msgEncoded = msg(line, user, keyStore, keyStorePassword);
				int id = getID(t[1], user);
				outStream.writeObject(t[0] + " " + t[1]);
				outStream.writeObject(msgEncoded);
				outStream.writeObject(id);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "c":
		case "collect":
			if(t.length == 2) {
				outStream.writeObject(line);
				if(!getMessages(t[1], user, keyStore, keyStorePassword))
					System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "h":
		case "history":
			if(t.length == 2) {
				outStream.writeObject(line);
				if(!getMessages(t[1], user, keyStore, keyStorePassword))
					System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "quit":
		case "q":
			outStream.writeObject(line);
			System.out.println((String) inStream.readObject());
			break;
		default:
			System.out.println("Metodo não existe");
			break;
		}
	}

	/**
	 * Gets all the messages encoded from a group and decodes
	 * @param groupID group where messages come from
	 * @param user
	 * @param keyStoreFile
	 * @param keyStorePassword
	 * @return messages decoded
	 */
	
	@SuppressWarnings("unused")
	private static boolean getMessages(String groupID, String user, String keyStoreFile, String keyStorePassword) {
		try {
			boolean b = (boolean) inStream.readObject();
			if(b) {
				String[] message = ((String) inStream.readObject()).split("\n");
				StringBuilder bob = new StringBuilder();
				bob.append("Messages:\n");
				for (String m : message) {
					bob.append(decryptMessage(groupID, user, keyStoreFile, keyStorePassword));
					bob.append("\n");
				}
				System.out.println(bob.toString());
			}
			return b;
		} catch(Exception e) {

			return false;
		}
	}

	/**
	 * Decrypt a group message
	 * @param groupID group where the message came from
	 * @param user 
	 * @param keyStoreFile
	 * @param keyStorePassword
	 * @return message decoded
	 * @throws FileNotFoundException
	 */
	
	private static String decryptMessage(String groupID, String user, String keyStoreFile, String keyStorePassword) throws FileNotFoundException {
		try {
			byte[] messageEncoded = (byte[]) inStream.readObject();
			String line = (String) inStream.readObject();
			byte[] key = Base64.getDecoder().decode(line);

			FileInputStream ins = new FileInputStream(keyStoreFile);
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(ins, keyStorePassword.toCharArray());   //Keystore password
			String alias = keyStore.aliases().asIterator().next();
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray());

			Cipher cRSA = Cipher.getInstance("RSA");
			cRSA.init(Cipher.UNWRAP_MODE, privateKey);

			Key keyEncoded = cRSA.unwrap(key, "RSA", Cipher.SECRET_KEY);
			SecretKeySpec keySpec = new SecretKeySpec(keyEncoded.getEncoded(), "AES");
			Cipher cAES = Cipher.getInstance("AES");
			cAES.init(Cipher.DECRYPT_MODE, keySpec);

			byte[] msg = cAES.doFinal(messageEncoded);
			String s = new String(msg);
			return s;
		} catch (Exception e) {

		}		
		return null;
	}

	/**
	 * Gets the ID of the group
	 * @param groupID group
	 * @param user user
	 * @return ID of the group
	 * @throws FileNotFoundException
	 */
	
	private static int getID(String groupID, String user) throws FileNotFoundException {
		File f = new File("Grupos/" + groupID + "/" + user + ".txt");
		String lastLine = "";
		Scanner sc = new Scanner(f);
		while(sc.hasNextLine()) {
			lastLine = sc.nextLine();
		}
		sc.close();
		int id = Integer.parseInt(Character.toString(lastLine.charAt(0)));
		return id;
	}

	/**
	 * Encodes the message sent by the user
	 * @param l line from console prompt, where l[1] = groupID
	 * @param user 
	 * @param keyStoreFile
	 * @param keyStorePassword
	 * @return message encoded
	 * @throws Exception
	 */
	
	private static byte[] msg(String l, String user, String keyStoreFile, String keyStorePassword) throws Exception {
		String[] line = l.split("\\s+");
		StringBuilder bob = new StringBuilder();
		for (int i = 2; i < line.length; i++) {
			bob.append(line[i] + " ");
		}
		File f = new File("Grupos/" + line[1] + "/" + user + ".txt");
		String lastLine = "";
		Scanner sc = new Scanner(f);
		while(sc.hasNextLine()) {
			lastLine = sc.nextLine();
		}
		sc.close();

		lastLine = lastLine.substring(2, lastLine.length());

		FileInputStream ins = new FileInputStream(keyStoreFile);
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, keyStorePassword.toCharArray());   //Keystore password
		String alias = keyStore.aliases().asIterator().next();
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray());

		Cipher cRSA = Cipher.getInstance("RSA");
		cRSA.init(Cipher.UNWRAP_MODE, privateKey);
		byte[] key = Base64.getDecoder().decode(lastLine);
		Key keyEncoded = cRSA.unwrap(key, "RSA", Cipher.SECRET_KEY);

		SecretKeySpec keySpec = new SecretKeySpec(keyEncoded.getEncoded(), "AES");
		Cipher cAES = Cipher.getInstance("AES");
		cAES.init(Cipher.ENCRYPT_MODE, keySpec);
		byte[] msgEncoded = cAES.doFinal(bob.toString().getBytes());

		return msgEncoded;
	}

	/**
	 * Generates a new from a keyStore
	 * @param keyStore
	 * @param keyStorePassword
	 */
	
	private static void newSecretKey(String keyStore, String keyStorePassword) {
		try {
			//Criar a chave
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			SecretKey key = kg.generateKey();

			@SuppressWarnings("unchecked")
			HashMap<String, String> users = (HashMap<String, String>) inStream.readObject();
			if(users != null) {
				for (String member : users.keySet()) {
					CertificateFactory fact = CertificateFactory.getInstance("X.509");
					FileInputStream is = new FileInputStream (CLIENT + users.get(member));
					X509Certificate cert = (X509Certificate) fact.generateCertificate(is);
					PublicKey publicKey = cert.getPublicKey();

					Cipher cRSA = Cipher.getInstance("RSA");
					cRSA.init(Cipher.WRAP_MODE, publicKey);
					byte[] encodedKey = cRSA.wrap(key);
					outStream.writeObject(encodedKey);
				}
			}
		} catch (Exception e) {

		}
	}

	/**
	 * Generates a new key the for the group
	 * @param keyStore of the owner
	 * @param keyStorePassword of the owner
	 */
	 private static void newGroup(String keyStore, String keyStorePassword) {
		try {
			boolean b = (boolean) inStream.readObject();
			if(b) {
				//Criar a chave
				KeyGenerator kg = KeyGenerator.getInstance("AES");
				kg.init(128);
				SecretKey key = kg.generateKey();

				Cipher cRSA = Cipher.getInstance("RSA");
				PublicKey publicKey = getCertificate(keyStore, keyStorePassword).getPublicKey();
				cRSA.init(Cipher.WRAP_MODE, publicKey);
				byte[] encodedKey = cRSA.wrap(key);
				outStream.writeObject(encodedKey);
			}
		} catch (NoSuchAlgorithmException e) {

		} catch (NoSuchPaddingException e) {

		} catch (Exception e) {

		}
	}

	/**
	 * Sends a photo through the socket to a server
	 * @param line line with the path to the photo
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */

	private static void post(String line) throws IOException, ClassNotFoundException {
		String[] t = line.split("\\s+");

		File file = new File(t[1]);
		if(file.exists()) {
			outStream.writeObject(true);
			int filesize = (int) file.length();
			outStream.writeObject(filesize);

			FileInputStream fis = new FileInputStream(file);
			byte[] buffer = new byte[MEGABYTE];
			while(fis.read(buffer, 0, buffer.length)> 0) {
				outStream.write(buffer, 0, buffer.length);
			}
			fis.close();
			System.out.println((String) inStream.readObject());
		} else {
			outStream.writeObject(false);
			System.out.println((String) inStream.readObject());
		}
	}

	/**
	 * Prints the options
	 */

	private static void printOptions() {
		System.out.println("Escolha uma opção: ");
		System.out.println("follow <userID>");
		System.out.println("unfollow <userID>");
		System.out.println("viewfollowers");
		System.out.println("post <photo>");
		System.out.println("wall <nPhotos>");
		System.out.println("like <photoID>");
		System.out.println("newgroup <groupID>");
		System.out.println("addu <userID> <groupID>");
		System.out.println("removeu <userID> <groupID>");
		System.out.println("ginfo [groupID]");
		System.out.println("msg <groupID> <msg>");
		System.out.println("collect <groupID>");
		System.out.println("history <groupID>");
		System.out.println("quit");
	}

	/**
	 * Receives photos through the socket from the server
	 * if the server have any to send
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */

	private static void wall() throws ClassNotFoundException, IOException {
		StringBuilder bob = new StringBuilder();
		boolean bb = true;
		while(bb){
			bb = (boolean) inStream.readObject();
			if(bb){
				bob.append("Foto: ");
				String name = (String) inStream.readObject();
				int filesize = (int) inStream.readObject();
				OutputStream os = new FileOutputStream("client/fotos/" + name);
				byte[] buffer = new byte[MEGABYTE];
				int read = 0;
				int remaining = filesize;
				while((read = inStream.read(buffer, 0, Math.min(buffer.length, remaining))) > 0) {
					remaining -= read;
					os.write(buffer, 0, read);
				}
				os.close();

				bob.append(inStream.readObject() + "\n");
			}	
		}
		if(bob.toString().equals("")) {
			System.out.println("There aren't any photos to see");
		}
		System.out.println(bob.toString());
	}
}
