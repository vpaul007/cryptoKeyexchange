package cryptoKeyexchange;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class F2ServerSkel {

	public static void main(String[] args) throws Exception {

		Socket s;
		ServerSocket ss = new ServerSocket(2000);
		while (true) {
			System.out.println("Server: waiting for connection ..");

			// Socket
			s = ss.accept();
			ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

			// Read DH params as string
			String dhParams = (String) ois.readObject();
			System.out.println(dhParams);
			// create DHParameterSpec object
			String[] values = dhParams.split(",");
			BigInteger pp = new BigInteger(values[0]);
			BigInteger g = new BigInteger(values[1]);
			int l = Integer.parseInt(values[2]);
			System.out.println("pp " + pp + "\ng " + g + "\nl " + l);
			
			
			
		    // Complete creation of DHParameterSpec object
			DHParameterSpec dhSpec = new DHParameterSpec(pp, g, l);
			
			// generate own DH key pair (using DHParameterSpec object)
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
			keyGen.initialize(dhSpec);
			KeyPair keypair = keyGen.generateKeyPair();
			PrivateKey sprivateKey = keypair.getPrivate();
			PublicKey spublicKey = keypair.getPublic();
			System.out.println(spublicKey);

			// read client public key using ois. and Downcast to PublicKey
//			String DHpublickey = (String) ois.readObject();
//			System.out.println(DHpublickey);

			// send own public key

			// generate symmetric key

			// Base64 encode the Secret key and print it out

		}
	}

}
