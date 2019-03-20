package nf.co.rogerioaraujo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.cert.X509Certificate;

public class ClientApp {
	private static final String KS_FILE = "certificate-files/my.keystore";
	private final static int port = 9000;
	private final static String host = "127.0.0.1";

	public static void main(String[] args) throws Exception {
		//
		String debug = "none";
		//
		try {
			System.out.println("Starting SSLClient....");
			System.out.println("Setting SSL debugging to :" + debug);
			System.setProperty("javax.net.debug", debug);
			// Get a TLS socket factory
			SSLSocketFactory socketFactory = ClientApp.getClientSocketFactory("TLS", KS_FILE);
			SSLSocket socket = (SSLSocket) socketFactory.createSocket(host, port);
			System.out.println("Socket : " + socket);
			
			//-------- INÍCIO DA ABSTRAÇÃO
			// handshake
			System.out.println("Handshake finished");
			socket.startHandshake();
			System.out.println("Handshake finished");

			// Get the SSLSession and print some of the session info
			SSLSession session = socket.getSession();
			System.out.println("Peer Host :" + session.getPeerHost());
			System.out.println("Name of the cipher suite :" + session.getCipherSuite());

			// Get the certificate Chain
			X509Certificate[] certificates = session.getPeerCertificateChain();

			// Print the distinguished Principal's name
			System.out.println("DN :" + certificates[0].getSubjectDN().getName());
			//-------- FIM DA ABSTRAÇÃO

			// Get the output stream
			PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
			/*
			 * Send the Get method
			 */
			out.println("GET HTTP/1.1");
			out.println();
			out.println();
			out.println("HELO");
			out.println();
			out.flush();

			/*
			 * Make sure there were no issues
			 */
			if (out.checkError()) {
				System.out.println("SSLClient:  java.io.PrintWriter error");
			}

			/*
			 * Read any responses
			 */
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String inputLine;
			while ((inputLine = in.readLine()) != null) {
				System.out.println(inputLine);
			}

			/*
			 * Close the stream and connection
			 */
			in.close();
			out.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static SSLSocketFactory getClientSocketFactory(String type, String filename) {

		if (type.equals("TLS")) {
			//
			SSLSocketFactory factory = null;
			System.out.println("Starting TLS Exchange....");
			//
			try { /*
					 * set up key manager to do server authentication
					 */
				SSLContext ctx;
				KeyManagerFactory kmf;
				TrustManagerFactory tmf;
				KeyStore ks;
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
				 * Get the default Java KeyStore
				 */
				ks = KeyStore.getInstance("JKS");
				/*
				 * Open the keystore that is a file called testkeys and the
				 * password
				 */
				ks.load(new FileInputStream(filename), passphrase);
				/*
				 * Initialize the KeyManager with the KeyStore
				 */
				kmf.init(ks, passphrase);
				tmf.init(ks);
				System.out.println("Opened KeyStore");
				/*
				 * Initialize the SSLContext with the keyManager
				 */
				ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
				/*
				 * Initialize the SocketFactory with the SSLContext
				 */
				factory = ctx.getSocketFactory();//
				return factory;
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			return (SSLSocketFactory) SSLSocketFactory.getDefault();
		}
		return null;
	}
}