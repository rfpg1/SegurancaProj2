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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Scanner;

import javax.crypto.Cipher;
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
			byte[] nonceEncrypted = encryptNonce(nonce, keyStore, keyStorePassword);
			if(registered) {
				outStream.writeObject(nonceEncrypted);
				boolean b = (boolean) inStream.readObject();
				if(b) {
					System.out.println("Authentication was successful");
				} else {
					System.out.println("Authentication  was not successful");
					return;
				}
			} else {
				outStream.writeObject(nonce);
				outStream.writeObject(nonceEncrypted);
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
				pedido(line); // Process the request
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
	
	private static byte[] encryptNonce(long nonce, String key, String pw) throws Exception {
		PrivateKey pKey = getPrivateKey(key, pw);
		Cipher cRSA = Cipher.getInstance("RSA"); //TODO TALVEZ METER EM FINAL
		cRSA.init(Cipher.ENCRYPT_MODE, pKey);
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(nonce);
		byte[] nonceBytes = buffer.array();
		return cRSA.doFinal(nonceBytes);
	}
	
	private static PrivateKey getPrivateKey(String key, String pw) throws Exception {
		FileInputStream ins = new FileInputStream(key);

		KeyStore keyStore = KeyStore.getInstance("JCEKS"); //TODO TALVEZ METER EM FINAL
		keyStore.load(ins, pw.toCharArray());   //Keystore password
		String alias = keyStore.aliases().asIterator().next();
		
		return (PrivateKey) keyStore.getKey(alias, pw.toCharArray());
	}
	
	private static Certificate getCertificate(String key, String pw) throws Exception {
		FileInputStream ins = new FileInputStream(key);

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, pw.toCharArray());   //Keystore password
		String alias = keyStore.aliases().asIterator().next();
		Certificate cert = keyStore.getCertificate(alias);
		return cert;
	}
	
	private static PublicKey getPublicKey(String key) throws Exception {
		FileInputStream ins = new FileInputStream("myKeys");

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, "testes".toCharArray());   //Keystore password
		Certificate cert = keyStore.getCertificate("keyRSA");
		return cert.getPublicKey();
	}

	/**
	 * Processes the request of the user
	 * @param line String with the method in the first position after a split by spaces
	 * @throws IOException 
	 * @throws ClassNotFoundException
	 */
	
	private static void pedido(String line) throws IOException, ClassNotFoundException {
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
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "a":
		case "addu":
			if(t.length == 3) {
				outStream.writeObject(line);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "r":
		case "removeu":
			if(t.length == 3) {
				outStream.writeObject(line);
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
				outStream.writeObject(line);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "c":
		case "collect":
			if(t.length == 2) {
				outStream.writeObject(line);
				System.out.println((String) inStream.readObject());
			} else {
				System.out.println("Executou mal o metodo");
			}
			break;
		case "h":
		case "history":
			if(t.length == 2) {
				outStream.writeObject(line);
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
				OutputStream os = new FileOutputStream("Fotos/" + name);
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
