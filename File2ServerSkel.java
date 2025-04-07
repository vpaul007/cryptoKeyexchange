import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import java.security.interfaces.*;
import java.util.Base64;

public class Server {

    public static void main(String[] args) throws Exception {
        System.out.println("Server is running...");

        // Step 1: Create a Server Socket to listen for connections
        ServerSocket serverSocket = new ServerSocket(2000);
        Socket socket = serverSocket.accept();

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        // Step 2: Receive Diffie-Hellman parameters from the client
        String params = (String) in.readObject();
        System.out.println("Received DH Parameters from client: " + params);

        // Step 3: Generate server's DH key pair
        String[] values = params.split(",");
        BigInteger p = new BigInteger(values[0]);
        BigInteger g = new BigInteger(values[1]);
        int l = Integer.parseInt(values[2]);
        DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey serverPrivateKey = keyPair.getPrivate();
        PublicKey serverPublicKey = keyPair.getPublic();

        // Step 4: Send the server's public key to the client
        out.writeObject(serverPublicKey);

        // Step 5: Receive the client's public key
        PublicKey clientPublicKey = (PublicKey) in.readObject();
        System.out.println("Received Client's Public Key: " + clientPublicKey);

        // Step 6: Generate shared secret key
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(serverPrivateKey);
        keyAgree.doPhase(clientPublicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();

        // Step 7: Derive AES secret key from the shared secret
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        // Step 8: Receive and decrypt the object sent by the client
        byte[] encryptedProduct = (byte[]) in.readObject();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedBytes = cipher.doFinal(encryptedProduct);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decryptedBytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        Product product = (Product) objectInputStream.readObject();

        // Step 9: Print the product details
        System.out.println("Decrypted Product: " + product);

        // Close resources
        objectInputStream.close();
        byteArrayInputStream.close();
        in.close();
        out.close();
        socket.close();
        serverSocket.close();
    }
}
