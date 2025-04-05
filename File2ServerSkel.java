import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class F1Server {

    public static void main(String[] args) throws Exception {
        System.out.println("Server");

        // Server socket
        ServerSocket serverSocket = new ServerSocket(2000);
        Socket s = serverSocket.accept();

        ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

        // Step 1: Receive DH parameters from the client
        String params = (String) ois.readObject();
        System.out.println("Received Params: " + params);

        // Step 2: Generate server's DH key pair using received parameters
        String[] values = params.split(",");
        BigInteger pp = new BigInteger(values[0]);
        BigInteger g = new BigInteger(values[1]);
        int l = Integer.parseInt(values[2]);
        DHParameterSpec dhSpec = new DHParameterSpec(pp, g, l);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair keypair = keyGen.generateKeyPair();
        PrivateKey sprivateKey = keypair.getPrivate();
        PublicKey spublicKey = keypair.getPublic();
        System.out.println("Server Public Key: " + spublicKey);

        // Step 3: Send server's public key to the client
        oos.writeObject(spublicKey);

        // Step 4: Receive client's public key
        PublicKey cpublicKey = (PublicKey) ois.readObject();
        System.out.println("Client Public Key: " + cpublicKey);

        // Step 5: Generate the shared secret using client's public key
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(sprivateKey);
        keyAgree.doPhase(cpublicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();

        // Step 6: Derive the symmetric key
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES"); // Use 128 bits for AES key
        System.out.println("Shared Secret (Base64): " + Base64.getEncoder().encodeToString(sharedSecret));

        // Step 7: Example: Decrypt the message received from the client
        byte[] encryptedMessage = (byte[]) ois.readObject();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        System.out.println("Decrypted Message: " + new String(decryptedMessage));

        // Close resources
        ois.close();
        oos.close();
        s.close();
        serverSocket.close();
    }
}
