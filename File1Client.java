import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class F1Client {

    public static void main(String[] args) throws Exception {
        System.out.println("Client");

        // Socket connection to the server
        InetAddress inet = InetAddress.getByName("localhost");
        Socket s = new Socket(inet, 2000);

        ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

        // Step 1: Generate DH parameters and send them to the server
        String params = generateParams();
        System.out.println("Params: " + params);

        // Send DH params to the server
        oos.writeObject(params);

        // Step 2: Generate client's DH key pair using received DH parameters
        String[] values = params.split(",");
        BigInteger pp = new BigInteger(values[0]);
        BigInteger g = new BigInteger(values[1]);
        int l = Integer.parseInt(values[2]);
        DHParameterSpec dhSpec = new DHParameterSpec(pp, g, l);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair keypair = keyGen.generateKeyPair();
        PrivateKey cprivateKey = keypair.getPrivate();
        PublicKey cpublicKey = keypair.getPublic();
        System.out.println("Client Public Key: " + cpublicKey);

        // Step 3: Send client's public key to the server
        oos.writeObject(cpublicKey);

        // Step 4: Receive server's public key
        PublicKey spublicKey = (PublicKey) ois.readObject();
        System.out.println("Server Public Key: " + spublicKey);

        // Step 5: Generate the shared secret using server's public key
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(cprivateKey);
        keyAgree.doPhase(spublicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();

        // Step 6: Derive the symmetric key (you could hash the shared secret for better security)
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES"); // Use 128 bits for AES key
        System.out.println("Shared Secret (Base64): " + Base64.getEncoder().encodeToString(sharedSecret));

        // Step 7: Example: Encrypt a simple message using the symmetric key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        String message = "Hello Server, this is client!";
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Step 8: Send encrypted message to the server (for demonstration)
        oos.writeObject(encryptedMessage);

        // Close resources
        ois.close();
        oos.close();
        s.close();
    }

    // Step 9: Generate DH parameters
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
