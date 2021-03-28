package server;

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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class SeiTchizServer {

	private final String FILE = "Users.txt";
	private final String GRUPOS = "Grupos/";
	private final String FOTOS = "Fotos/";
	private final String USERS = "Users/";
	private HashMap<String, ArrayList<String>> users = new HashMap<>();
	private final File[] pastas = {new File("Fotos"), new File("Grupos"), new File("Users")};

	class ServerThread implements Runnable{

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
				String passwd = null;

				user = (String) inStream.readObject();
				//passwd = (String)inStream.readObject();
				System.out.println("Received user and password");

				if(users.get(user) != null) {
					String pw = users.get(user).get(1); // Tudo deu certo;
					if(pw.equals(passwd)) {
						outStream.writeObject(1);
					} else {
						outStream.writeObject(2); // User existe mas a pw não é aquela
						System.out.println("Wrong password");
						return;
					}
				} else { // User ainda não existe
					outStream.writeObject(3);
					outStream.writeObject("Insert your name");
					String nome = (String) inStream.readObject();
					registaUser(user, passwd, nome);
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
		 * @throws IOException
		 */

		private void addNewMember(String owner, String userID, String groupID) throws IOException {
			List<String> grupos = Arrays.asList(getFromDoc("Grupos", "Grupos").split(","));
			if(grupos.contains(groupID) && getFromDoc(GRUPOS + groupID, "Owner").equals(owner) && !owner.equals(userID)) {
				List<String> members = Arrays.asList(getFromDoc(GRUPOS + groupID, "Members").split(","));
				if(!members.contains(userID)) {
					int gID = Integer.parseInt(getFromDoc(GRUPOS + groupID, "ID"));
					addToDoc(GRUPOS + groupID, "Members", userID);
					addToDoc(USERS + userID, "Grupos", groupID + "/" +  gID + "/" + gID);
					outStream.writeObject("Member added\n");
				} else {
					outStream.writeObject("Member is already in group\n");
				}
			} else {
				outStream.writeObject("This isn't the owner of the group or group does not exist or you are trying to add yourself\n");
			}
		}
		
		/**
		 * Creates a new group
		 * Sends a message if the groupID already exists
		 * @param user user logged in and the owner of the group
		 * @param groupID ID of the new group
		 * @throws IOException
		 */

		private void newGroup(String user, String groupID) throws IOException {
			List<String> grupos = Arrays.asList(getFromDoc("Grupos", "Grupos").split(","));
			if(!grupos.contains(groupID)) {
				addToDoc("Grupos", "Grupos", groupID);
				addToDoc(USERS + user, "Grupos", groupID + "/0/0");
				addToDoc(USERS + user, "Owner", groupID);
				PrintWriter pw = new PrintWriter(GRUPOS + groupID + ".txt");
				pw.println("Owner:" + user);
				pw.println("Members:");
				pw.println("ID:0");
				pw.print("Chat:\n");
				pw.close();
				outStream.writeObject("Group created\n");
			} else {
				outStream.writeObject("Group with that name already exists\n");
			}

		}
		
		/**
		 * Likes a photo 
		 * @param user user liking the photo
		 * @param photoID
		 * @throws IOException
		 * @requires photoID has to be like User:PhotoID
		 */

		private void like(String user, String photoID) throws IOException { //photoID é user:id
			String[] profilePhoto = photoID.split(":");
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
		 * @throws IOException
		 */

		private void wall(String user, int nfotos) throws IOException {
			List<String> seguindo = Arrays.asList(getFromDoc(USERS + user, "Seguindo").split(","));
			Scanner fotos = new Scanner(new File("Fotos.txt"));
			while(fotos.hasNextLine()) {
				String[] t = fotos.nextLine().split(":");
				if(seguindo.contains(t[0]) && nfotos > 0) {
					outStream.writeObject(nfotos > 0);
					nfotos--;
					sendPhoto(t[0], t[1]);
					sendIDAndLikes(t[0], t[1]);
				}
			}
			outStream.writeObject(false);
			fotos.close();
		}

		/**
		 * Gets the number of likes of the photo with the id from user
		 * @param user users 
		 * @param id id of the photo
		 * @throws IOException
		 */
		private void sendIDAndLikes(String user, String id) throws IOException {
			String[] photos = getFromDoc(USERS + user, "Fotos").split(",");
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
		 * @throws ClassNotFoundException
		 * @throws IOException
		 */

		private void post(String user) throws ClassNotFoundException, IOException {
			int id = Integer.parseInt(getFromDoc(USERS + user, "ID"));
			id++;
			boolean b = (boolean) inStream.readObject();
			if(b) {
				saveImage(user, id);
				addToDoc(USERS + user, "Fotos", String.valueOf(id) + "/0");
				addToDoc("Fotos", null, user + ":" + id);
				changeID(USERS + user, id);

				outStream.writeObject("Photo added\n");
				outStream.flush();
				inStream.skip(Long.MAX_VALUE); // TODO: Pensar nisto, já pensei não consigo chegar a outra conclusão
			} else {
				outStream.writeObject("Photo does not exists!\n");
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
		 * @throws IOException
		 */
		private void viewFollowers(String user) throws IOException{
			Scanner sc = new Scanner(new File(USERS + user+ ".txt"));
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
		}

		/**
		 * Unfollows the requested profile
		 * @param user current user
		 * @param userASeguir user to unfollow
		 * @throws IOException
		 */
		private void unfollow(String user, String userASeguir) throws IOException {
			if(users.get(userASeguir) != null) { //Caso o userASeguir exista
				if(seguir(user, userASeguir)) {
					removeFromDoc(USERS + userASeguir, "Seguidores", user);
					removeFromDoc(USERS + user, "Seguindo", userASeguir);
					outStream.writeObject("User unfollowed\n");
				} else {
					outStream.writeObject("User isn't being followed\n");
				}
			} else {
				outStream.writeObject("User does not exist\n");
			}
		}

		/**
		 * Follows the requested profile
		 * @param user current user
		 * @param userASeguir user to follow
		 * @throws IOException
		 */
		private void follow(String user, String userASeguir) throws IOException {
			if(users.get(userASeguir) != null) { //Caso o userASeguir exista
				if(!seguir(user, userASeguir)) {
					addToDoc(USERS + userASeguir, "Seguidores", user);
					addToDoc(USERS + user, "Seguindo", userASeguir);
					outStream.writeObject("User followed\n");
				} else {
					outStream.writeObject("User is already being followed\n");
				}
			} else {
				outStream.writeObject("User does not exist\n");
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
			Scanner sc = new Scanner(new File(USERS + userASeguir + ".txt"));
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
		private void registaUser(String user, String passwd, String name) throws FileNotFoundException {
			ArrayList<String> list = new ArrayList<>();
			list.add(name);
			list.add(passwd);
			users.put(user, list);
			PrintWriter pw = new PrintWriter(FILE);
			for(String s : users.keySet()) {
				pw.print(s + ":");
				ArrayList<String> lista = users.get(s);
				for (int i = 0; i < lista.size(); i++) {
					pw.print(lista.get(i));
					if(i + 1 < lista.size()) {
						pw.print(":");
					}
				}
				pw.println();
			}
			pw.close();
			PrintWriter t = new PrintWriter(USERS + user + ".txt");
			t.println("User:" + user);
			t.println("Seguidores:");
			t.println("Seguindo:");
			t.println("Fotos:");
			t.println("ID:0");
			t.println("Grupos:");
			t.print("Owner:");
			t.close();
		}
	}

	public static void main(String[] args) throws NumberFormatException, IOException {
		System.out.println("servidor: main");
		System.setProperty("javax.net.ssl.keyStore", "server/" + args[1]);
		System.setProperty("javax.net.ssl.keyStorePassword", args[2]);
		SeiTchizServer server = new SeiTchizServer();
		server.startServer(Integer.parseInt(args[0]));
	}

	@SuppressWarnings("resource")
	private void startServer(int port) throws IOException {
		//ServerSocket sSoc = null;
		ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();	
		SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(port);
		try {
			loadUsers();
			criaPastas();
			//sSoc = new ServerSocket(port);
		} catch (IOException e) {
			e.printStackTrace();
		}

		while(true) {
			try {
				//Socket inSoc = sSoc.accept();
				//ServerThread newServerThread = new ServerThread(inSoc);
				//newServerThread.run();
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
	 * @throws FileNotFoundException
	 */
	private void loadUsers() throws FileNotFoundException {
		Scanner sc = new Scanner(new File(FILE));
		while(sc.hasNextLine()) {
			String line = sc.nextLine();
			// user:nome:pw
			String[] credencias = line.split(":");
			ArrayList<String> list = new ArrayList<>();
			list.add(credencias[1]);
			list.add(credencias[2]);
			users.put(credencias[0], list);
		}

		sc.close();
	}
}
