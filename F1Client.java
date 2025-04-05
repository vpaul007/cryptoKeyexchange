package cryptoKeyexchange;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class F1Client {

   public static void main(String[] args) throws Exception {

      System.out.println("Client");

      // Socket
      InetAddress inet = InetAddress.getByName("localhost");
      Socket s = new Socket(inet, 2000);

      ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
      ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
      // get DH params as string
      String params = generateParams();
      System.out.println("Params "+params);
      
      // send DH params as string
      oos.writeObject(params);
      
      // create DHParameterSpec object
      String[] values = params.split(",");
      BigInteger pp = new BigInteger(values[0]);
      BigInteger g = new BigInteger(values[1]);
      int l = Integer.parseInt(values[2]);
      DHParameterSpec dhSpec = new DHParameterSpec(pp, g, l);

      
      // Generate a DH key pair  (using DHParameterSpec object)
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
      keyGen.initialize(dhSpec);
      KeyPair keypair = keyGen.generateKeyPair();
      PrivateKey cprivateKey = keypair.getPrivate();
      PublicKey cpublicKey = keypair.getPublic();
      System.out.println(cpublicKey);

    
      // send own public key using oos.
    oos.writeObject(cpublicKey);
      // read servers public key using ois. and Downcast to PublicKey
    

      // generate symmetric key

      // Base64 encode the secret key 

      // Print the secret key 

   }

   public static String generateParams() {

      String s = null;
      try {
         // Create the parameter generator for a 1024-bit DH key pair
         AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
         paramGen.init(1024);

         // Generate the parameters
         AlgorithmParameters params = paramGen.generateParameters();
         DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
         s = dhSpec.getP() + "," + dhSpec.getG() + "," + dhSpec.getL();

      } catch (Exception e) {
         e.printStackTrace();
      }
      return s;
   }
}
