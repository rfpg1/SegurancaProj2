package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;

public class SeiTchiz {

	private static final int MEGABYTE = 1024;
	private static ObjectOutputStream outStream;
	private static ObjectInputStream inStream;

	public static void main(String[] args) {
		Socket socket = null;
		String[] AdressEporta = args[0].split(":");
		Scanner sc = new Scanner(System.in);
		String id = args[1]; // ID of the user
		System.out.println("User ID: " + id);
		try {
			String adress = AdressEporta[0];
			int porta = Integer.parseInt(AdressEporta[1]);
			socket = new Socket(adress, porta);
			String pw = null; // Password of the user
			if (args.length == 2)  {
				System.out.println("Insira a sua password: ");
				pw = sc.nextLine();
			} else {
				pw = args[2];
			}
			outStream = new ObjectOutputStream(socket.getOutputStream());
			outStream.writeObject(id);
			outStream.writeObject(pw);
			inStream = new ObjectInputStream(socket.getInputStream());
			int autenticado = (int) inStream.readObject();
			switch (autenticado) {
			case 1: //User atenticado e deu certo
				System.out.println("Correct Password!");
				break;
			case 2: //User existe mas a pw não é essa
				System.out.println("Wrong Password!");
				sc.close();
				socket.close();
				return;
				//break;
			case 3: //User não existe
				System.out.println((String)inStream.readObject());
				String nome = sc.nextLine();
				outStream.writeObject(nome);
				System.out.println("User registered\n");
				break;
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
			System.out.println("Ficheiro não existe");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
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
				bob.append("Fotos: \n");
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
