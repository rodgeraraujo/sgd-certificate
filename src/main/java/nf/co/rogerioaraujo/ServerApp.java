package nf.co.rogerioaraujo;

/**
 *
 * Created by rodger on Mar 20, 2019 10:14:34 AM
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

//create certificate:
//  openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out pub.crt -keyout priv.key
public class ServerApp extends Thread {
	private static final String KS_FILE = "certificate-files/my.keystore";
	private final Socket socket;

	public ServerApp(Socket s) {
		socket = s;
	}

	public void run() {
		try {
			// log
			System.out.println("Received client connection....");

			// Get the Input and Output Socket Streams
			PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String inputLine;

			// Read until all input is read
			while ((inputLine = in.readLine()) != null) {
				System.out.println(inputLine);
			}
			out.println("Post HTTP/1.1");
			out.flush();

			// Close the stream and connection
			in.close();
			out.close();
		} catch (IOException ex) {
			System.out.println("Error: " + ex.getMessage());
			ex.printStackTrace();
		} finally {
			try {
				System.out.println("Closing Client Socket......");
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static ServerSocketFactory getServerSocketFactory(String type, String filename) {
		if (type.equals("TLS")) {
			SSLServerSocketFactory ssf = null;
			System.out.println("Starting TLS Exchange....");
			try {
				/*
				 * set up key manager to do server authentication
				 */
				SSLContext ctx;//contexto de segurança
				KeyManagerFactory kmf;//gerenciador de chaves
				TrustManagerFactory tmf;//validar o certificado
				KeyStore ks;//chaves (repositório)
				/*
				 * passphrase is the password for the store
				 */
				char[] passphrase = "123456".toCharArray();
				/*
				 * Use TLS
				 */
				ctx = SSLContext.getInstance("TLS");
				/*
				 * Get an instance of the X509
				 */
				kmf = KeyManagerFactory.getInstance("SunX509");
				/*
				 * Get an instance of the X509
				 */
				tmf = TrustManagerFactory.getInstance("SunX509");
				/*
				 * Get the default Java KeyStore (JKS)
				 */
				ks = KeyStore.getInstance("JKS");
				/*
				 * Open the keystore that is a file called testkeys and the
				 * password
				 */
				ks.load(new FileInputStream(filename), passphrase);//filename (local do my.keystore)
				/*
				 * Initialize the KeyManager with the KeyStore
				 */
				kmf.init(ks, passphrase);//carrgar a chave privada
				tmf.init(ks);//carregar a chave pública
				System.out.println("Opened KeyStore");
				/*
				 * Initialize the SSLContext with the keyManager
				 */
				ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
				/*
				 * Initialize the ServerSocketFactory with the SSLContext 12
				 * Chapter 23: Java Secure Socket Extension Chapter 23: Java
				 * Secure Socket Extension 13
				 */
				ssf = ctx.getServerSocketFactory();
				return ssf;
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			return ServerSocketFactory.getDefault();
		}
		return null;
	}

	public static void main(String[] args) throws Exception {
		// set debug
		String debug = "true";
		// enbale log
		System.out.println("Setting SSL debugging to :" + debug);
		System.setProperty("javax.net.debug", debug);
		//
		// ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
		ServerSocketFactory ssf = ServerApp.getServerSocketFactory("TLS", KS_FILE);
		ServerSocket ss = ssf.createServerSocket(9000);
		((SSLServerSocket) ss).setNeedClientAuth(true);
		//permitir mais de uma conexão
		while (true) {
			new ServerApp(ss.accept()).start();
		}
	}

}