import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.interfaces.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class Client {

    public static void main(String[] args) throws Exception {
        System.out.println("Client is running...");

        // Step 1: Connect to the server
        Socket socket = new Socket("localhost", 2000);
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        // Step 2: Generate Diffie-Hellman parameters and key pair
        String params = generateParams();
        out.writeObject(params);
        System.out.println("Sent DH Parameters to server: " + params);

        // Step 3: Generate client's DH key pair
        String[] values = params.split(",");
        BigInteger p = new BigInteger(values[0]);
        BigInteger g = new BigInteger(values[1]);
        int l = Integer.parseInt(values[2]);
        DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey clientPrivateKey = keyPair.getPrivate();
        PublicKey clientPublicKey = keyPair.getPublic();

        // Step 4: Send the client's public key to the server
        out.writeObject(clientPublicKey);

        // Step 5: Receive server's public key
        PublicKey serverPublicKey = (PublicKey) in.readObject();
        System.out.println("Received Server's Public Key: " + serverPublicKey);

        // Step 6: Generate shared secret key
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(clientPrivateKey);
        keyAgree.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        
        // Step 7: Derive AES secret key from the shared secret
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        // Step 8: Create an object to encrypt
        Product product = new Product("Laptop", "High-end gaming laptop", 50);

        // Step 9: Encrypt the object
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(product);
        byte[] productBytes = byteArrayOutputStream.toByteArray();
        byte[] encryptedProduct = cipher.doFinal(productBytes);

        // Step 10: Send encrypted object to server
        out.writeObject(encryptedProduct);

        // Close streams and socket
        objectOutputStream.close();
        byteArrayOutputStream.close();
        in.close();
        out.close();
        socket.close();
    }

    // Step 11: Generate Diffie-Hellman Parameters
    public static String generateParams() {
        String result = "";
        try {
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);

            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
            result = dhSpec.getP() + "," + dhSpec.getG() + "," + dhSpec.getL();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
}
