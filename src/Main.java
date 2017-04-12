import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        //Todo Figure out how to run from commandline
        //Configuration steps:  Add Bouncy Castle jars to project, test if we actually need both.
        //Check Java security to make sure the JRE can do some security magic... (Potential Error: Invalid Key Length)

        //Required for Bouncy Castle Encryption
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        //Checks if files already exist, if not, create the files, if yes, ask for password.
        System.out.println("Password Manager 1.0");
        File master_passwd_file = new File("master_passwd");
        File passwd_file = new File("passwd_file");
        if (!(master_passwd_file.exists() && passwd_file.exists())) {
            //Registers a new user
            System.out.println("New User, please enter in a Master Password:");
            Scanner scan = new Scanner(System.in);
            String mastPass = scan.nextLine();
            System.out.println(mastPass);
            createFiles(mastPass);
        } else {
            //Checks given password with a saved password
            System.out.println("Welcome Back. Please enter your password:");
            Scanner scan = new Scanner(System.in);
            String mastPass = scan.nextLine();
            while (!readMasterPass(mastPass)) {
                System.out.println("WRONG MASTER PASSWORD!");
                System.out.println("Type <0> to quit");
                mastPass = scan.nextLine();
                if (mastPass.equals("0")) {
                    System.out.println("Exiting...");
                    System.exit(0);
                }
            }

            //Main Menu code
            while (true) {
                System.out.println("\n\n\n");
                System.out.println("Welcome User! Type in a command to begin.");
                System.out.println("1: Check Integrity");
                System.out.println("2: Register Account");
                System.out.println("3: Delete Account");
                System.out.println("4: Change Account");
                System.out.println("5: Get Password");
                System.out.println("0: Exit");
                int option = scan.nextInt();
                switch (option) {
                    case 1:
                        System.out.println("Check Integrity TODO");
                        break;
                    case 2:
                        System.out.println("Register Account TODO");
                        break;
                    case 3:
                        System.out.println("Delete Account TODO");
                        break;
                    case 4:
                        System.out.println("Change Account TODO");
                        break;
                    case 5:
                        System.out.println("Get Password TODO");
                        break;
                    case 0:
                        System.out.println("Exiting...");
                        System.exit(0);
                        break;
                    default:
                        System.out.println("Not a command");
                        break;
                }
            }
        }
        //For AES encryption, look at Chapter 2 examples
    }

    /**
     * Reads the master_passwd file and checks if it matches the given password
     *
     * @param masterPass Given password
     * @return returns boolean if the passwords match
     * @throws IOException IOException if file is not found.
     */
    private static boolean readMasterPass(String masterPass) throws IOException {
        Path path = Paths.get("master_passwd");
        byte[] data = Files.readAllBytes(path);
        byte[] salt = Arrays.copyOf(data, 32);
        byte[] hash = Arrays.copyOfRange(data, 32, 64);
        return checkMasterPassword(masterPass, salt, hash);
    }

    /**
     * Writes the master_passwd file with the given hashedkey and salf
     *
     * @param hashedKey Hashed key and salt value
     * @param salt      Salt given in plaintext and concatenated to the front
     * @throws IOException Thrown if file doesn't exist
     */
    //TODO add integrity check write code to here
    private static void writeMasterPass(byte[] hashedKey, byte[] salt) throws IOException {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream("master_passwd");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(hashedKey.length + salt.length);
        outputStream.write(salt);
        outputStream.write(hashedKey);

        byte outPut[] = outputStream.toByteArray();
        assert fos != null;
        fos.write(outPut);
        fos.close();
    }

    /**
     * Takes in a random salt and master password and hashes it with SHA256
     *
     * @param mastPass Given master password
     * @param salt     Random salt 256-bits
     * @return New hashed key
     * @throws UnsupportedEncodingException Thrown if SHA256 isn't supported
     */
    private static byte[] setMasterPass(String mastPass, byte[] salt) throws UnsupportedEncodingException {
        int hashBytes = 32;
        //Create new hash with SHA256
        PKCS12ParametersGenerator kdf = new PKCS12ParametersGenerator(new SHA256Digest());
        kdf.init(mastPass.getBytes("UTF-8"), salt, 1000);
        //Returns the hased value
        return ((KeyParameter) kdf.generateDerivedMacParameters(8 * hashBytes)).getKey();
    }

    /**
     * Checks if master password file and the read password match up
     *
     * @param password     Typed in password
     * @param salt         Salt extracted from master_passwd file
     * @param readPassword Read password extracted from master_passwd file
     * @return Boolean comparing the values of the hashedToCheck and read passwords
     * @throws UnsupportedEncodingException Thrown if SHA256 is not supported
     */
    private static boolean checkMasterPassword(String password, byte[] salt, byte[] readPassword) throws UnsupportedEncodingException {
        int hashBytes = 32;
        //Check file, pass in salt and run the check
        // to check a password, given the known previous salt and hash:
        PKCS12ParametersGenerator kdf = new PKCS12ParametersGenerator(new SHA256Digest());
        kdf.init(password.getBytes("UTF-8"), salt, 1000);

        byte[] hashToCheck = ((KeyParameter) kdf.generateDerivedMacParameters(8 * hashBytes)).getKey();
        // if the bytes of hashToCheck don't match the bytes of readPassword
        // that means the password is invalid
        return Arrays.equals(readPassword, hashToCheck);

    }

    /**
     * Checks and creates master_passwd and passwd_file
     *
     * @param mastPass String that is password typed in
     */
    private static void createFiles(String mastPass) {
        try {

            File master__passwd_file = new File("master_passwd");
            File passwd_file = new File("passwd_file");

            if (master__passwd_file.createNewFile()) {
                int seedBytes = 32;
                SecureRandom rng = new SecureRandom();
                byte[] salt = rng.generateSeed(seedBytes);
                writeMasterPass(setMasterPass(mastPass, salt), salt);
            } else {
                System.out.println("Error: Master Password File already exists.");
            }
            if (!passwd_file.createNewFile()) {
                System.out.println("Error: Password File already exists.");
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
