package server;
//TODO New-group depois de explica��o de algu�m!
//TODO ID do grupo passar a chamar LastMessage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import facade.exceptions.ApplicationException;

public class SeiTchizServer {

	private static final String SERVER = "server/";
	private final String FILE = "Users.txt";
	private final String GRUPOS = "Grupos/";
	private final String FOTOS = "Fotos/";
	private final String USERS = "Users/";
	private final String CLIENT = "client/";
	private HashMap<String, String> users = new HashMap<>();
	private final File[] pastas = {new File("Fotos"), new File("Grupos"), new File("Users")};
	private String keyStore;
	private String keyStorePassword;

	class ServerThread implements Runnable {

		private final int MEGABYTE = 1024;
		private Socket socket = null;
		private ObjectOutputStream outStream = null;
		private ObjectInputStream inStream = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
		}

		public void run() {
			try {
				outStream = new ObjectOutputStream(socket.getOutputStream());
				inStream = new ObjectInputStream(socket.getInputStream());

				String user = null;

				user = (String) inStream.readObject();
				System.out.println("Received user and password");
				long l = 0;
				try {
					l = generateNonce();
				} catch (ApplicationException e) {
					System.out.println(e.getMessage());
				}
				boolean registered = users.get(user) != null;
				outStream.writeObject(l);
				outStream.writeObject(registered);
				if(registered) {
					byte[] nonceEncrypted =  (byte[]) inStream.readObject();
					CertificateFactory fact = CertificateFactory.getInstance("X.509");
					FileInputStream is = new FileInputStream (CLIENT + users.get(user));
					X509Certificate cert = (X509Certificate) fact.generateCertificate(is);
					byte[] nonceB = decryptNonce(nonceEncrypted, cert.getPublicKey());
					ByteBuffer bb = ByteBuffer.wrap(nonceB);
					long t = bb.getLong();
					if(l == t) {
						outStream.writeObject(true);
					} else {
						outStream.writeObject(false);
					}
				} else {
					long nonce = (long) inStream.readObject();
					byte[] nonceEncrypted =  (byte[]) inStream.readObject();
					Certificate cert = (Certificate) inStream.readObject();
					byte[] nonceB = decryptNonce(nonceEncrypted, cert.getPublicKey());
					ByteBuffer bb = ByteBuffer.wrap(nonceB);
					long t = bb.getLong();
					if(nonce == t) {
						registUser(user, "certClient" + user + ".cer");
						outStream.writeObject(true);
					} else {
						outStream.writeObject(false);
					}
				}
				boolean b = true;
				while(b) {
					String[] line = ((String) inStream.readObject()).split(" ");
					switch(line[0]) {
					case "f":
					case "follow":
						follow(user, line[1]);
						break;
					case "u":
					case "unfollow":
						unfollow(user, line[1]);
						break;
					case "v":
					case "viewfollowers":
						viewFollowers(user);
						break;
					case "p":
					case "post":
						post(user);
						break;
					case "w":
					case "wall":
						wall(user, Integer.parseInt(line[1]));
						break;
					case "l":
					case "like":
						like(user, line[1]);
						break;
					case "n":
					case "newgroup":
						newGroup(user, line[1]);
						break;
					case "a":
					case "addu":
						addNewMember(user, line[1], line[2]);
						break;
					case "r":
					case "removeu":
						removeMember(user, line[1], line[2]);
						break;
					case "g":
					case "ginfo":
						if(line.length == 2){
							ginfo(user, line[1]);
						}else{
							ginfo(user);
						}
						break;
					case "m":
					case "msg":
						StringBuilder bob = new StringBuilder();
						for (int i = 2; i < line.length; i++) {
							bob.append(line[i] + " ");
						}
						msg(user, line[1], bob.toString());
						break;
					case "c":
					case "collect":
						collect(user, line[1]);
						break;
					case "h":
					case "history":
						history(user, line[1]);
						break;
					default:
						b = false;
						outStream.writeObject("Left\n");
						break;
					}	
				}

				outStream.close();
				inStream.close();
				socket.close();

			} catch(IOException e) {
				e.printStackTrace();				
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (ApplicationException e) {
				try {
					outStream.writeObject(false);
				} catch (IOException e1) {

				}
				System.out.println(e.getMessage());
			} catch (CertificateException e) {

			} catch (Exception e) {
			} 
		}

		private byte[] decryptNonce(byte[] nonce, PublicKey publicKey) throws ApplicationException {
			try {
				Cipher cRSA = Cipher.getInstance("RSA");
				cRSA.init(Cipher.DECRYPT_MODE, publicKey);
				return cRSA.doFinal(nonce);
			} catch (Exception e) {
				throw new ApplicationException("Decription Error");
			}		
		}

		private long generateNonce() throws ApplicationException {
			try {
				SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
				byte[] bytes = new byte[1024/8];
				sr.nextBytes(bytes);
				// Create two secure number generators with the same seed
				int seedByteCount = 10;
				byte[] seed = sr.generateSeed(seedByteCount);
				sr = SecureRandom.getInstance("SHA1PRNG");
				sr.setSeed(seed);
				SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG");
				sr2.setSeed(seed);
				return sr.nextLong();
			} catch (NoSuchAlgorithmException e) {
				throw new ApplicationException("Este mm nah existe");
			}
		}

		/**
		 * Returns all messages read by this user
		 * if group doesn't exist a message is sent
		 * if user isn't part of that group a message is sent
		 * @param user user logged in
		 * @param groupID gets the all messages from this group
		 * @throws IOException 
		 */

		private void history(String user, String groupID) throws IOException {
			try {
				List<String> gruposAux = Arrays.asList(getFromDoc("Grupos", "Grupos").split(","));
				List<String> membersAux = Arrays.asList(getFromDoc(GRUPOS + groupID, "Members").split(","));
				if (!gruposAux.contains(groupID)) { // Grupo n�o existe
					outStream.writeObject(groupID + " does not exist");
					// Caso o user n�o fa�a parte do grupo nem � o owner
				} else if (!membersAux.contains(user) && !getFromDoc(GRUPOS + groupID, "Owner").equals(user)) {
					outStream.writeObject("You are not a member of group " + groupID);
				} else { // Tudo correu bem
					String[] grupos = getFromDoc(USERS + user, "Grupos").split(",");
					int idHistory = 0;
					int idCollect = 0;
					for(String grupo : grupos) {
						String[] info = grupo.split("/");
						if (info[0].equals(groupID)) {
							idCollect = Integer.parseInt(info[1]); // Vai buscar o ID da ultima mesagem que ele leu
							idHistory = Integer.parseInt(info[2]); // Vai buscar o ID de quando ele entrou para o grupo
						}
					}
					Scanner sc = new Scanner(new File(USERS + user + ".txt"));
					StringBuilder bob = new StringBuilder();
					String[] chat = getChat(groupID); // Vai buscar todo o chat do grupo
					for (int i = idHistory; i < idCollect; i++) {
						bob.append(chat[i] + "\n");
					}
					if(bob.toString().equals("")) {
						outStream.writeObject("Zero messages in your personal history of group" + groupID + "\n");
					} else {
						outStream.writeObject(bob.toString());
					}
					sc.close();
				}
			} catch (FileNotFoundException e) {
				System.out.println("Ficheiro n�o existe");
				outStream.writeObject("Group does not exist\n");
			} catch (IOException e) {
				e.printStackTrace();
			}

		}

		/**
		 * Gets all the messages from that group that haven't been collected yet
		 * if group doesn't exist a message is sent
		 * if user isn't part of that group a message is sent
		 * @param user user to collect the messages
		 * @param groupID group to collect the messages
		 * @throws IOException
		 */

		private void collect (String user, String groupID) throws IOException {
			if (!getFromDoc("Grupos", "Grupos").contains(groupID)) { // Verifica se o grupo existe
				outStream.writeObject(groupID + " does not exist\n");
			} else if (!getFromDoc(USERS + user, "Grupos").contains(groupID) && 
					// Verifica se o user faz parte do grupo, como owner ou membro
					!getFromDoc(GRUPOS + groupID, "Owner").equals(user)) { 
				outStream.writeObject("You are not in the group " + groupID);
			} else {
				String[] grupos = getFromDoc(USERS + user, "Grupos").split(","); //Vai buscar todos os grupos do user
				int currID = 0;
				for (String i : grupos) {
					String[] g = i.split("/");
					if (g[0].equals(groupID)) {
						currID = Integer.parseInt(g[1]); 
					}
				}
				int lastID = Integer.parseInt(getFromDoc(GRUPOS + groupID, "ID"));
				String[] chat = getChat(groupID);
				if (chat.length == 0) {
					outStream.writeObject("Chat doesn't contain any message\n");
				} 
				StringBuilder bob = new StringBuilder();
				for (int i = currID; i < lastID; i++) {
					bob.append(chat[i] + "\n");	            	
				}
				if(bob.toString().equals("")){
					outStream.writeObject("There are no new messages\n");
				} else {
					outStream.writeObject(bob.toString());
					changeGID(user, groupID,lastID);
				}
			}
		}
		/**
		 * Changes the ID of the group in a user
		 * @param user user logged in
		 * @param groupID group chosen
		 * @param id id to change to
		 * @throws FileNotFoundException
		 */

		private void changeGID(String user, String groupID, int id) throws FileNotFoundException {
			Scanner sc = new Scanner(new File(USERS + user + ".txt"));
			StringBuilder bob = new StringBuilder();
			while(sc.hasNextLine()) {
				String line = sc.nextLine();
				String[] sp = line.split(":");
				if(sp[0].equals("Grupos")) {
					bob.append("Grupos:");
					String[] grupos = sp[1].split(",");
					for(String grupo : grupos) {
						String[] info = grupo.split("/");
						if(info[0].equals(groupID)) {
							bob.append(groupID + "/" + id + "/" + info[2] + ",");
						} else { 
							bob.append(grupo + ",");
						}
						bob.append("\n");
					}
				} else {
					bob.append(line + "\n");
				}
			}
			PrintWriter pw = new PrintWriter(USERS + user + ".txt");
			pw.print(bob.toString());
			pw.close();
			sc.close();
		}

		/**
		 * Gets the chat of a group
		 * @param groupID group the get the chat from
		 * @return all the messages sent to that group
		 * @throws FileNotFoundException
		 */

		private String[] getChat(String groupID) throws FileNotFoundException {
			Scanner sc = new Scanner(new File(GRUPOS + groupID + ".txt"));
			int ID = Integer.parseInt(getFromDoc(GRUPOS + groupID, "ID"));
			boolean b = false;
			String[] msgs = new String[ID];
			int i = 0;
			while (sc.hasNextLine()) {
				if (b) {
					msgs[i] = sc.nextLine();
					i++;
				} else {
					if (sc.nextLine().equals("Chat:")) {
						b = true;
					}
				}
			}
			sc.close();
			return msgs;
		}

		/**
		 * Sends a message to a group
		 * if group doesn't exist a message is sent
		 * if user isn't part of that group a message is sent
		 * @param user user sending the message
		 * @param groupID group the message is sent to
		 * @param msg message sent to a group
		 * @throws IOException
		 */

		private void msg(String user, String groupID, String msg) throws IOException {
			List<String> grupos = Arrays.asList(getFromDoc("Grupos", "Grupos").split(","));
			if(grupos.contains(groupID)) {
				List<String> members = Arrays.asList(getFromDoc(GRUPOS + groupID, "Members").split(","));
				if(members.contains(user) || getFromDoc(GRUPOS + groupID, "Owner").equals(user)) {
					int id = Integer.parseInt(getFromDoc(GRUPOS + groupID, "ID"));
					id++;
					changeID(GRUPOS + groupID, id);
					newMessage(groupID, "Chat", msg);
					outStream.writeObject("Message received!\n");					
				} else {
					outStream.writeObject("You are not in that group!\n");
				}
			} else {
				outStream.writeObject("Group does not exist!\n");
			}
		}

		/**
		 * Add the message to the chat in a group
		 * @param groupID group the message is added to
		 * @param tag tag to add to (Always = Chat)
		 * @param info message to be added
		 * @throws FileNotFoundException
		 */

		private void newMessage(String groupID, String tag, String info) throws FileNotFoundException{
			Scanner sc = new Scanner(new File(GRUPOS + groupID + ".txt"));
			StringBuilder bob = new StringBuilder();
			while(sc.hasNextLine()) {
				String line = sc.nextLine();
				String[] sp = line.split(":");
				if(sp[0].equals(tag)) {
					bob.append("Chat:\n");
					while(sc.hasNextLine()) {
						bob.append(sc.nextLine() + "\n");
					}
					bob.append(info + System.lineSeparator());
				} else {
					bob.append(line + "\n");
				}
			}
			sc.close();
			PrintWriter pw = new PrintWriter(GRUPOS + groupID + ".txt");
			pw.print(bob.toString());
			pw.close();
		}

		/**
		 * Gets all the info about the groups of the user logged in
		 * @param user user logged in
		 * @throws FileNotFoundException
		 * @throws IOException
		 */

		private void ginfo(String user) throws FileNotFoundException, IOException {
			String grupos = getFromDoc(USERS + user, "Grupos");
			String owner = getFromDoc(USERS + user, "Owner");
			StringBuilder bob = new StringBuilder();
			if(grupos == ""){
				bob.append("You aren't a member of any group" + "\n");
			}else {
				bob.append("You are member of: ");
				String[] g = grupos.split(",");
				for(String gr : g){
					bob.append(gr.split("/")[0] + ",");
				}
				bob.deleteCharAt(bob.length() - 1);
				bob.append("\n");
			}

			if(owner == ""){
				bob.append("You aren't the owner of any group" + "\n");
			}else {
				bob.append("You are the owner of: " + owner.substring(0, owner.length() -1) + "\n");
			}
			outStream.writeObject(bob.toString());
		}

		/**
		 * Gets all the info about the group given
		 * if group doesn't exist a message is sent
		 * if user isn't part of that group a message is sent
		 * @param user
		 * @param groupID
		 * @throws FileNotFoundException
		 * @throws IOException
		 */

		private void ginfo(String user, String groupID) throws FileNotFoundException, IOException{
			File grupo = new File(GRUPOS + groupID + ".txt");
			if(grupo.exists()){
				String owner = getFromDoc(GRUPOS + groupID, "Owner");
				List<String> m = Arrays.asList(getFromDoc(GRUPOS + groupID, "Members").split(","));
				if(!user.equals(owner) && !m.contains(user)){
					outStream.writeObject("You don't belong to this group\n");
				} else {
					String members = getFromDoc(GRUPOS + groupID, "Members");
					if(members != ""){
						outStream.writeObject("The owner of the group is: " + owner + "\n" +
								"The members of the group are: " + members.substring(0, members.length() -1) + "\n");
					} else{
						outStream.writeObject("The owner of the group is: " + owner + "\n" +
								"The group has no members \n");
					}
				}
			}else {
				outStream.writeObject("The group doesn't exist\n");
			}
		}

		/**
		 * Removes a member from a group
		 * if group doesn't exist a message is sent
		 * if user isn't part of that group a message is sent
		 * also can't remove the owner of the group
		 * @param owner owner of the group
		 * @param userID user to be removed from the group
		 * @param groupID group to be removed from
		 * @throws IOException
		 */

		private void removeMember(String owner, String userID, String groupID) throws  IOException {
			List<String> grupos = Arrays.asList(getFromDoc("Grupos", "Grupos").split(","));
			if(grupos.contains(groupID) && getFromDoc(GRUPOS + groupID, "Owner").equals(owner) && !owner.equals(userID)) {
				List<String> members = Arrays.asList(getFromDoc(GRUPOS + groupID, "Members").split(","));
				if(members.contains(userID)) {
					String[] gru = getFromDoc(USERS + userID, "Grupos").split(",");
					int currID = 0;
					for (String i : gru) {
						String[] g = i.split("/");
						if (g[0].equals(groupID)) {
							currID = Integer.parseInt(g[1]);
						}
					}
					removeFromDoc(GRUPOS + groupID, "Members", userID);
					removeFromDoc(USERS + userID, "Grupos", groupID + "/" + currID);
					outStream.writeObject("Member removed\n");
				} else {
					outStream.writeObject("Member isn't in the group\n");
				}
			} else {
				outStream.writeObject("This isn't the owner of the group or group does not exist or you are trying to remove yourself\\n");
			}
		}

		/**
		 * Adds a member from a group
		 * if group doesn't exist a message is sent
		 * if user isn't part of that group a message is sent
		 * also can't add himself to the group
		 * @param owner owner of the group
		 * @param userID user to be added to the group
		 * @param groupID group to be added to
		 * @throws Exception 
		 */

		private void addNewMember(String owner, String userID, String groupID) throws Exception {
			try {
				decrypt("Grupos.txt");
				decrypt(GRUPOS + groupID + ".txt");
				decrypt(USERS + userID + "/" + userID + ".txt");
				List<String> grupos = Arrays.asList(getFromDoc("Grupos", "Grupos").split(","));
				if(grupos.contains(groupID) && getFromDoc(GRUPOS + groupID, "Owner").equals(owner) && !owner.equals(userID)) {
					List<String> members = Arrays.asList(getFromDoc(GRUPOS + groupID, "Members").split(","));
					if(!members.contains(userID)) {
						int gID = Integer.parseInt(getFromDoc(GRUPOS + groupID, "ID"));
						addToDoc(GRUPOS + groupID, "Members", userID);
						addToDoc(USERS + userID + "/" + userID, "Grupos", groupID + "/" +  gID + "/" + gID);
						//Criar a chave
						KeyGenerator kg = KeyGenerator.getInstance("AES");
						kg.init(128);
						SecretKey key = kg.generateKey();
						
						String i = getFromDoc(GRUPOS + groupID, "Identificador");
						int id = Integer.parseInt(i.substring(0, i.length() - 1));
						removeFromDoc(GRUPOS + groupID, "Identificador", String.valueOf(id));
						id++;
						addToDoc(GRUPOS + groupID, "Identificador", String.valueOf(id));
						members = Arrays.asList(getFromDoc(GRUPOS + groupID, "Members").split(","));
						for(String member : members) {
							Cipher cRSA = Cipher.getInstance("RSA");
							PublicKey publicKey = getCertificate(member).getPublicKey();
							cRSA.init(Cipher.WRAP_MODE, publicKey);
							byte[] encodedKey = cRSA.wrap(key);
							FileOutputStream fos = new FileOutputStream(USERS + member + "/" + groupID + id + ".key");
							fos.write(encodedKey);
							fos.close();
						}
						Cipher cRSA = Cipher.getInstance("RSA");
						PublicKey publicKey = getCertificate(owner).getPublicKey();
						cRSA.init(Cipher.WRAP_MODE, publicKey);
						byte[] encodedKey = cRSA.wrap(key);
						FileOutputStream fos = new FileOutputStream(USERS + owner + "/" + groupID + id + ".key");
						fos.write(encodedKey);
						fos.close();
						outStream.writeObject("Member added\n");
					} else {
						outStream.writeObject("Member is already in group\n");
					}
				} else {
					outStream.writeObject("This isn't the owner of the group or group does not exist or you are trying to add yourself\n");
				}
				encrypt(USERS + userID + "/" + userID + ".txt");
				encrypt(GRUPOS + groupID + ".txt");
				encrypt("Grupos.txt");
			} catch (Exception e) {
				encrypt("Grupos.txt");
				encrypt(USERS + userID + "/" + userID + ".txt");
				encrypt(GRUPOS + groupID + ".txt");
				System.out.println("Error encryption or decryption method -> addNewMember");
			}
		}

		/**
		 * Creates a new group
		 * Sends a message if the groupID already exists
		 * @param user user logged in and the owner of the group
		 * @param groupID ID of the new group
		 * @throws Exception 
		 */

		private void newGroup(String user, String groupID) throws Exception {
			try {
				decrypt("Grupos.txt");
				List<String> grupos = Arrays.asList(getFromDoc("Grupos", "Grupos").split(","));
				if(!grupos.contains(groupID)) {
					decrypt(USERS + user + "/" + user+ ".txt");
					addToDoc("Grupos", "Grupos", groupID);
					addToDoc(USERS + user + "/" + user, "Grupos", groupID + "/0/0");
					addToDoc(USERS + user + "/" + user, "Owner", groupID);
					PrintWriter pw = new PrintWriter(GRUPOS + groupID + ".txt");
					pw.println("Owner:" + user);
					pw.println("Members:");
					pw.println("ID:0");
					pw.println("Identificador:0,");
					pw.print("Chat:\n");
					pw.close();
					outStream.writeObject("Group created\n");
					//Criar a chave
					KeyGenerator kg = KeyGenerator.getInstance("AES");
					kg.init(128);
					SecretKey key = kg.generateKey();
					//Criar o cipher
					Cipher cRSA = Cipher.getInstance("RSA");
					PublicKey publicKey = getCertificate(user).getPublicKey();
					cRSA.init(Cipher.WRAP_MODE, publicKey);
					byte[] encodedKey = cRSA.wrap(key);
					FileOutputStream fos = new FileOutputStream(USERS + user + "/" + groupID + "0.key");
					fos.write(encodedKey);
					fos.close();
					encrypt(USERS + user + "/" + user+ ".txt");
					encrypt(GRUPOS + groupID + ".txt");
				} else {
					outStream.writeObject("Group with that name already exists\n");
				}
				encrypt("Grupos.txt");
			} catch (Exception e ) {
				encrypt("Grupos.txt");
				encrypt(USERS + user + ".txt");
				System.out.println("Error encryption or decryption method -> newGroup");
			}
		}

		private Certificate getCertificate(String user) throws Exception {
			try {
				decrypt(FILE);
				String certFile = getFromDoc("Users", user);
				CertificateFactory fact = CertificateFactory.getInstance("X.509");
				FileInputStream is = new FileInputStream (CLIENT + certFile);
				X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
				encrypt(FILE);
				return cer;
			} catch (Exception e) {
				encrypt(FILE);
				System.out.println("Error encryption or decryption method -> getCertificate");
			}
			return null;
		}


		/**
		 * Likes a photo 
		 * @param user user liking the photo
		 * @param photoID
		 * @throws IOException
		 * @requires photoID has to be like User:PhotoID
		 */
//TODO mudar as pastas
		private void like(String user, String photoID) throws IOException { //photoID é user:id
			try {
				String[] profilePhoto = photoID.split(":");
				decrypt(USERS + profilePhoto[0] + ".txt");
				if(verifyUser(profilePhoto[0])) {
					boolean b = false;
					String[] photos = getFromDoc(USERS + profilePhoto[0], "Fotos").split(",");
					for(String photo : photos) {
						if(photo.split("/")[0].equals(profilePhoto[1])) {
							removeFromDoc(USERS + profilePhoto[0], "Fotos", photo);
							int likes = Integer.parseInt(photo.split("/")[1]) + 1;
							String newInfo = photo.split("/")[0] + "/" + likes;
							addToDoc(USERS + profilePhoto[0], "Fotos", newInfo);
							b = true;
						}
					}
					if(b) {
						outStream.writeObject("Liked photo\n");
					} else {
						outStream.writeObject("Photo does not exist!\n");
					}
				} else {
					outStream.writeObject("User does not exist!\n");
				}
				encrypt(USERS + profilePhoto[0] + ".txt");
			} catch(Exception e) {
				System.out.println("Error encryption or decryption method -> like");
			}	
		}

		/**
		 * Verifies if the user exists
		 * @param user user to be verified
		 * @return true if exists
		 */

		private boolean verifyUser(String user) {
			return users.get(user) != null;
		}

		/**
		 * Sends the last n photos of the users being followed (in total)
		 * @param user user logged in
		 * @param nfotos number of photos
		 * @throws Exception 
		 * @throws IOException
		 */

		private void wall(String user, int nfotos) throws Exception {
			try {
				decrypt(USERS + user + "/" + user + ".txt");
				decrypt("Fotos.txt");
				List<String> seguindo = Arrays.asList(getFromDoc(USERS + user + "/" + user, "Seguindo").split(","));
				Scanner fotos = new Scanner(new File("Fotos.txt"));
				while(fotos.hasNextLine()) {
					String[] t = fotos.nextLine().split(":");
					if(seguindo.contains(t[0]) && nfotos > 0) {
						outStream.writeObject(nfotos > 0);
						nfotos--;
						sendPhoto(t[0], t[1]);
						decrypt(USERS + t[0] + "/" + t[0] + ".txt");
						sendIDAndLikes(t[0], t[1]);
						encrypt(USERS + t[0] + "/" + t[0] + ".txt");
					}
				}
				outStream.writeObject(false);
				fotos.close();
				encrypt(USERS + user + "/" + user + ".txt");
				encrypt("Fotos.txt");
			} catch (Exception e) {
				encrypt(USERS + user + "/" + user + ".txt");
				encrypt("Fotos.txt");
				System.out.println("Error encryption or decryption method -> wall");
			}
		}

		/**
		 * Gets the number of likes of the photo with the id from user
		 * @param user users 
		 * @param id id of the photo
		 * @throws IOException
		 */
		private void sendIDAndLikes(String user, String id) throws IOException {
			String[] photos = getFromDoc(USERS + user + "/" + user, "Fotos").split(",");
			for(String photo : photos) {
				if(photo.split("/")[0].equals(id)) {
					outStream.writeObject(user + ": (id/likes) " + photo);
				}
			}
		}

		/**
		 * Sends the photo to the client
		 * @param user current user 
		 * @param photo photo that will be sent
		 * @throws IOException
		 */

		private void sendPhoto(String user, String photo) throws IOException {
			File file = new File(FOTOS + user + ";" + photo + ".jpg");
			InputStream is = new FileInputStream(file);
			byte[] buffer = new byte[MEGABYTE];
			int length = 0;
			outStream.writeObject(user + ";" + photo + ".jpg");
			int filesize = (int) file.length();
			outStream.writeObject(filesize);
			while((length = is.read(buffer, 0, buffer.length)) > 0) {
				outStream.write(buffer, 0, length);
			}
			is.close();
		}

		/**
		 * Gets the information with the requested tag from the file docName
		 * @param docName name of the file 
		 * @param tag requested tag
		 * @throws FileNotFoundException
		 */

		private String getFromDoc(String docName, String tag) throws FileNotFoundException {
			Scanner sc = new Scanner(new File(docName + ".txt"));
			while(sc.hasNextLine()){
				String line = sc.nextLine();
				String[] sp = line.split(":");
				if(sp[0].equals(tag)) {
					if(sp.length > 1){
						sc.close();
						return sp[1];
					}
				}
			}
			sc.close();
			return "";
		}

		/**
		 * Posts the photo the current user requested to post
		 * @param user current user 
		 * @throws Exception 
		 * @throws ClassNotFoundException
		 * @throws IOException
		 */

		private void post(String user) throws Exception {
			try {
				decrypt(USERS + user + "/" + user + ".txt");
				decrypt("Fotos.txt");
				int id = Integer.parseInt(getFromDoc(USERS + user + "/" + user, "ID"));
				id++;
				boolean b = (boolean) inStream.readObject();
				if(b) {
					saveImage(user, id);
					addToDoc(USERS + user + "/" + user, "Fotos", String.valueOf(id) + "/0");
					addToDoc("Fotos", null, user + ":" + id);
					changeID(USERS + user + "/" + user, id);

					outStream.writeObject("Photo added\n");
					outStream.flush();
					inStream.skip(Long.MAX_VALUE);
				} else {
					outStream.writeObject("Photo does not exists!\n");
				}
				encrypt(USERS + user + "/" + user + ".txt");
				encrypt("Fotos.txt");
			} catch(Exception e) {
				encrypt(USERS + user + "/" + user + ".txt");
				encrypt("Fotos.txt");
				System.out.println("Error encryption or decryption method -> post");
			}

		}

		/**
		 * Updates the ID from the next photo
		 * @param user user to be updated
		 * @param id new id
		 * @throws FileNotFoundException
		 */
		private void changeID(String user, int id) throws FileNotFoundException {
			Scanner sc = new Scanner(new File(user + ".txt"));
			StringBuilder bob = new StringBuilder();
			while(sc.hasNextLine()) {
				String line = sc.nextLine();
				String[] sp = line.split(":");
				if(sp[0].equals("ID")) {
					bob.append("ID:" + id + "\n");
				} else {
					bob.append(line + "\n");
				}
			}
			PrintWriter pw = new PrintWriter(user + ".txt");
			pw.print(bob.toString());
			pw.close();
			sc.close();
		}

		/**
		 * Saves the image in the server under the users profile
		 * @param user current user
		 * @param id id of the photo
		 * @throws FileNotFoundException
		 * @throws IOException
		 */
		private void saveImage(String user, int id) throws ClassNotFoundException, IOException {          
			int filesize = (int) inStream.readObject();	
			FileOutputStream fos = new FileOutputStream(FOTOS + user + ";" + id + ".jpg");

			byte[] buffer = new byte[MEGABYTE];
			int read = 0;
			int remaining = filesize;
			while((read = inStream.read(buffer, 0, Math.min(buffer.length, remaining))) > 0) {
				remaining -= read;
				fos.write(buffer, 0, read);
			}
			fos.close();
		}

		/**
		 * Shows the current user his followers
		 * @param user current user
		 * @throws Exception 
		 */
		private void viewFollowers(String user) throws Exception{
			try {
				decrypt(USERS + user + "/" + user + ".txt");
				Scanner sc = new Scanner(new File(USERS + user + "/" + user + ".txt"));
				while(sc.hasNextLine()) {
					String line = sc.nextLine();
					String[] sp = line.split(":");
					if(sp[0].equals("Seguidores")) {
						if(sp.length > 1) {
							outStream.writeObject(sp[1].substring(0, sp[1].length() - 1) + "\n");
						} else {
							outStream.writeObject("You don't have any followers\n");
						}
						break;
					}
				}
				sc.close();
				encrypt(USERS + user + "/" + user + ".txt");
			} catch (Exception e) {
				encrypt(USERS + user + "/" + user + ".txt");
				System.out.println("Error encryption or decryption method -> viewFollowers");
			}
		}

		/**
		 * Unfollows the requested profile
		 * @param user current user
		 * @param userASeguir user to unfollow
		 * @throws Exception 
		 */
		private void unfollow(String user, String userASeguir) throws Exception {
			try {
				decrypt(USERS + userASeguir + "/" + userASeguir + ".txt");
				decrypt(USERS + user + "/" + user + ".txt");
				if(users.get(userASeguir) != null) { //Caso o userASeguir exista
					if(seguir(user, userASeguir)) {
						removeFromDoc(USERS + userASeguir + "/" + userASeguir, "Seguidores", user);
						removeFromDoc(USERS + user + "/" + user, "Seguindo", userASeguir);
						outStream.writeObject("User unfollowed\n");
					} else {
						outStream.writeObject("User isn't being followed\n");
					}
				} else {
					outStream.writeObject("User does not exist\n");
				}
				encrypt(USERS + userASeguir + "/" + userASeguir+ ".txt");
				encrypt(USERS + user + "/" + user + ".txt");
			} catch (Exception e) {
				encrypt(USERS + user + "/" + user + ".txt");
				System.out.println("Error encryption or decryption method -> unfollow");
			}
		}

		/**
		 * Follows the requested profile
		 * @param user current user
		 * @param userASeguir user to follow
		 * @throws Exception 
		 */
		private void follow(String user, String userASeguir) throws Exception {
			try {
				decrypt(USERS + userASeguir + "/" + userASeguir + ".txt");
				decrypt(USERS + user + "/" + user + ".txt");
				if(users.get(userASeguir) != null) { //Caso o userASeguir exista
					if(!seguir(user, userASeguir)) {
						addToDoc(USERS + userASeguir + "/" + userASeguir, "Seguidores", user);
						addToDoc(USERS + user + "/" + user, "Seguindo", userASeguir);
						outStream.writeObject("User followed\n");
					} else {
						outStream.writeObject("User is already being followed\n");
					}
				} else {
					outStream.writeObject("User does not exist\n");
				}
				encrypt(USERS + userASeguir + "/" + userASeguir + ".txt");
				encrypt(USERS + user + "/" + user + ".txt");
			} catch (Exception e) {
				encrypt(USERS + user + "/" + user + ".txt");
				encrypt(USERS + userASeguir + "/" + userASeguir + ".txt");
				System.out.println("Error encryption or decryption method -> follow");
			}
		}

		/**
		 * Returns true if user follows userASeguir
		 * @param user user
		 * @param userASeguir userASeguir
		 * @return True if user follows userASeguir, false if not
		 * @throws IOException
		 */
		private boolean seguir(String user, String userASeguir) throws FileNotFoundException {
			Scanner sc = new Scanner(new File(USERS + userASeguir + "/" + userASeguir + ".txt"));
			while(sc.hasNextLine()) {
				String line = sc.nextLine();
				String[] sp = line.split(":");
				if(sp[0].equals("Seguidores")) {
					if(sp.length > 1) {
						sc.close();
						return sp[1].contains(user + ",");
					}
				}
			}
			sc.close();
			return false;
		}

		/**
		 * Removes the info from a certain tag from the file docName
		 * @param docName name of the file
		 * @param tag tag that will be edited
		 * @param info info that will be removed
		 * @throws FileNotFoundException
		 */
		private void removeFromDoc (String docName, String tag, String info) throws FileNotFoundException{
			File doc = new File(docName + ".txt");
			Scanner sc = new Scanner (doc);
			StringBuilder bob = new StringBuilder();

			while(sc.hasNextLine()){
				String line = sc.nextLine();
				String[] sp = line.split(":");
				if(sp[0].equals(tag)) {
					String[] aux = line.split(info + ",");
					if(aux.length > 1) {
						line = aux[0] + aux[1];
					} else {
						line = aux[0];
					}
				} 
				bob.append(line + "\n");
			}

			PrintWriter pt = new PrintWriter (doc);
			pt.print(bob.toString());
			sc.close();
			pt.close();
		}

		/**
		 * Adds the info to a certain tag to the file docName
		 * @param docName name of the file
		 * @param tag tag that will be edited
		 * @param info info that will be added
		 * @throws FileNotFoundException
		 */
		private void addToDoc (String docName, String tag, String info) throws FileNotFoundException{
			File doc = new File(docName + ".txt");
			Scanner sc = new Scanner (doc);
			StringBuilder bob = new StringBuilder();
			if(tag != null) {
				while(sc.hasNextLine()){
					String line = sc.nextLine();
					String[] sp = line.split(":");
					if(sp[0].equals(tag)) {
						line = line + (info + ",");
					} 
					bob.append(line + "\n");
				}
			} else {
				StringBuilder minibob = new StringBuilder();
				while(sc.hasNextLine()){
					String line = sc.nextLine();
					minibob.append(line + "\n");
				}
				bob.append(info + "\n");
				bob.append(minibob.toString());
			}
			PrintWriter pt = new PrintWriter (doc);
			pt.print(bob.toString());
			sc.close();
			pt.close();
		}

		/**
		 * Registers a new user
		 * @param user new user id
		 * @param passwd new user password
		 * @param name new user name
		 * @throws FileNotFoundException
		 */
		private void registUser(String user, String certificate) throws Exception {
			decrypt(FILE);
			File f = new File(USERS + user + "/");
			f.mkdir();
			users.put(user, certificate);
			PrintWriter pw = new PrintWriter(FILE);
			for(String s : users.keySet()) {
				pw.println(s + ":" + users.get(s));
			}
			pw.close();
			PrintWriter t = new PrintWriter(USERS + user + "/" + user + ".txt");
			t.println("User:" + user);
			t.println("Seguidores:");
			t.println("Seguindo:");
			t.println("Fotos:");
			t.println("ID:0");
			t.println("Grupos:");
			t.print("Owner:");
			t.close();
			encrypt(USERS + user + "/" + user + ".txt");
			encrypt(FILE);
		}
	}

	public static void main(String[] args) {
		System.out.println("servidor: main");
		System.setProperty("javax.net.ssl.keyStore", SERVER + args[1]);
		System.setProperty("javax.net.ssl.keyStorePassword", args[2]);
		SeiTchizServer server = new SeiTchizServer();
		server.startServer(Integer.parseInt(args[0]), args[1], args[2]);
	}

	private void encrypt(String file) throws Exception {
		PrivateKey privateKey = getPrivateKey("server/" + this.keyStore, this.keyStorePassword);
		Cipher cRSA = Cipher.getInstance("RSA");
		cRSA.init(Cipher.ENCRYPT_MODE, privateKey);

		File f = new File(file);
		FileInputStream rawDataFromFile = new FileInputStream(f);
		byte[] plainText = new byte[(int)f.length()];
		rawDataFromFile.read(plainText);
		rawDataFromFile.close();
		byte[] encodedKey = cRSA.doFinal(plainText);
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(encodedKey);
		fos.close();
	}

	private void decrypt(String file) throws Exception {
		PublicKey publicKey = getPublicKey("server/" + this.keyStore, this.keyStorePassword);
		File f = new File(file);
		if(f.length() > 0) {
			Cipher cRSA = Cipher.getInstance("RSA");
			cRSA.init(Cipher.DECRYPT_MODE, publicKey);
			FileInputStream rawDataFromKey = new FileInputStream(f);
			byte[] keyText = new byte[(int)f.length()];
			rawDataFromKey.read(keyText);
			rawDataFromKey.close();
			byte[] dataDecrypted = cRSA.doFinal(keyText);
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(dataDecrypted);
			fos.close();
		}
	}

	private static PrivateKey getPrivateKey(String keyStoreFile, String keyStorePassword) throws Exception {
		FileInputStream ins = new FileInputStream(keyStoreFile);

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, keyStorePassword.toCharArray());   //Keystore password
		String alias = keyStore.aliases().asIterator().next();
		return (PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray());
	}

	private PublicKey getPublicKey(String keyStoreFile, String keyStorePassword) throws Exception {
		FileInputStream ins = new FileInputStream(keyStoreFile);

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, keyStorePassword.toCharArray());   //Keystore password
		String alias = keyStore.aliases().asIterator().next();
		Certificate cert = keyStore.getCertificate(alias);
		return cert.getPublicKey();
	}

	@SuppressWarnings("resource")
	private void startServer(int port, String keyStore, String keyStorePassword){
		ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();	
		SSLServerSocket ss = null;
		this.keyStore = keyStore;
		this.keyStorePassword = keyStorePassword;
		try {
			loadUsers();
			criaPastas();
			ss = (SSLServerSocket) ssf.createServerSocket(port);
		} catch (Exception e) {
			e.printStackTrace();
		}

		while(true) {
			try {
				new ServerThread(ss.accept()).run();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		//sSoc.close();
	}

	private void criaPastas() {
		for(File pasta : pastas) {
			if(!pasta.exists()) {
				pasta.mkdir();
			}
		}
	}

	/**
	 * Load the users from our file
	 * @throws Exception 
	 * @throws FileNotFoundException
	 */
	private void loadUsers() throws Exception {
		try {
			decrypt(FILE);
			Scanner sc = new Scanner(new File(FILE));
			while(sc.hasNextLine()) {
				String line = sc.nextLine();
				// user:certificate
				String[] credencias = line.split(":");
				users.put(credencias[0], credencias[1]);
			}
			sc.close();
			encrypt(FILE);
		} catch (Exception e) {
			encrypt(FILE);
		}
	}
}
