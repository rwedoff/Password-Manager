import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    private static HashMap<String, Entry> entryList = new HashMap<>();

    //TODO change to random iv and legit key.
    static byte[] ivBytes = new byte[]{
            0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    static byte[] keyBytes = new byte[]{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
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
        }
        //Checks given password with a saved password
        System.out.println("Welcome! Please enter your password:");
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
        //TODO check ingerity here
        try {
            decryptFile(keyBytes, ivBytes);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
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
            System.out.println("0: Save/Exit");
            int option = scan.nextInt();
            switch (option) {
                case 1:
                    System.out.println("Check Integrity TODO");
                    break;
                case 2:
                    addAccount();
                    break;
                case 3:
                    deleteAccount();
                    break;
                case 4:
                    System.out.println("Change Account TODO");
                    changeAccount();
                    break;
                case 5:
                    getAccount();
                    break;
                case 0:
                    System.out.println("Saving...");
                    try {
                        encryptFile(keyBytes, ivBytes);
                    } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
                        e.printStackTrace();
                    }
                    System.out.println("Exiting...");
                    System.exit(0);
                    break;
                //TODO REMOVE; only for debug!
                case 9:
                    System.out.println("Printing List");
                    printEntryList();
                    break;
                default:
                    System.out.println("Not a command");
                    break;
            }
        }

    }


    /**
     * Reads the master_passwd file and checks if it matches the given password
     *
     * @param masterPass Given password
     * @return returns boolean if the passwords match
     * @throws IOException IOException if file is not found.
     */
    private static boolean readMasterPass(String masterPass) throws IOException, NoSuchAlgorithmException {
        Path path = Paths.get("master_passwd");
        byte[] data = Files.readAllBytes(path);
        byte[] salt = Arrays.copyOf(data, 32);
        byte[] hash = Arrays.copyOfRange(data, 32, data.length);
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
    private static byte[] setMasterPass(String mastPass, byte[] salt) throws IOException, NoSuchAlgorithmException {
        /*int hashBytes = 32;
        //Create new hash with SHA256
        PKCS12ParametersGenerator kdf = new PKCS12ParametersGenerator(new SHA256Digest());
        kdf.init(mastPass.getBytes("UTF-8"), salt, 1000);
        //Returns the hased value
        return ((KeyParameter) kdf.generateDerivedMacParameters(8 * hashBytes)).getKey();*/
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        bout.write(salt);
        bout.write(mastPass.getBytes());

        return md.digest(bout.toByteArray());

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
    private static boolean checkMasterPassword(String password, byte[] salt, byte[] readPassword) throws IOException, NoSuchAlgorithmException {
        int hashBytes = 32;
        //Check file, pass in salt and run the check
        // to check a password, given the known previous salt and hash:

        /*
        PKCS12ParametersGenerator kdf = new PKCS12ParametersGenerator(new SHA256Digest());
        kdf.init(password.getBytes("UTF-8"), salt, 1000);

        byte[] hashToCheck = ((KeyParameter) kdf.generateDerivedMacParameters(8 * hashBytes)).getKey();
        */


        MessageDigest md = MessageDigest.getInstance("SHA-512");
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        bout.write(salt);
        bout.write(password.getBytes());
        byte[] hashToCheck = md.digest(bout.toByteArray());

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

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Given the static EntryList, this encrypts the whole file and writes to passwd_file
     *
     * @param keyBytes Key to encrypt
     * @param ivBytes  Random IV
     * @throws InvalidAlgorithmParameterException Bouncy Castle required
     * @throws InvalidKeyException                Bouncy Castle required
     * @throws NoSuchPaddingException             Bouncy Castle required
     * @throws NoSuchAlgorithmException           Bouncy Castle required
     * @throws NoSuchProviderException            Bouncy Castle required
     * @throws IOException                        Caught if passwd_file can't be written to.
     */
    private static void encryptFile(byte[] keyBytes, byte[] ivBytes) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        //TODO think about, is the key just the masterPass file?  Should the masterpass file be unencrypted?
        //Todo add a key and iv file
        //Todo where do we save the IV, master pass? In plaintext in passwd_file?
        //TODO should we decrypt first and then re-encrypt with the new record (auto saving)
        //TODO run encryption after every operation?
        //TODO What do we do if there are multiple accounts with the same domain? HashMap doesn't allow duplicates

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        ByteArrayOutputStream input = new ByteArrayOutputStream();

        for (String mapKey : entryList.keySet()) {
            input.write(Utils.toByteArray(entryList.get(mapKey).toString()));
        }

        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        ByteArrayInputStream bIn = new ByteArrayInputStream(input.toByteArray());
        CipherInputStream cIn = new CipherInputStream(bIn, cipher);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = cIn.read()) >= 0) {
            bOut.write(ch);
        }

        byte[] cipherText = bOut.toByteArray();

        //System.out.println("cipher: " + Utils.toHex(cipherText));

        try (OutputStream outputStream = new FileOutputStream("passwd_file")) {
            bOut.writeTo(outputStream);
        }
    }

    /**
     * Decrypts the whole file and builds Entry objects
     *
     * @param keyBytes Key to encrypt the file
     * @param ivBytes  Random IV used for encryption
     * @throws IOException                        Bouncy Castle required
     * @throws NoSuchPaddingException             Bouncy Castle required
     * @throws NoSuchAlgorithmException           Bouncy Castle required
     * @throws NoSuchProviderException            Bouncy Castle required
     * @throws InvalidAlgorithmParameterException Bouncy Castle required
     * @throws InvalidKeyException                Thrown if passwd_file can't be read.
     * @see Entry
     */
    private static void decryptFile(byte[] keyBytes, byte[] ivBytes) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        entryList.clear();
        //Decrypt the whole password file
        Path path = Paths.get("passwd_file");
        byte[] data = Files.readAllBytes(path);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);

        cOut.write(data);

        cOut.close();

        byte[] fileBytes = bOut.toByteArray();

        int fileSize = fileBytes.length;
        int j = 0;
        for (int i = 0; i < fileSize; i++) {
            if (i % 240 == 0) {
                j += 240;
                entryList.put(Utils.toStringRange(fileBytes, i, j - 160), new Entry(Utils.toStringRange(fileBytes, i, j)));
            }
        }
    }

    /**
     * Adds an account/Entry to static Entry list
     *
     * @see Entry
     */
    private static void addAccount() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Account Name:");
        String accountName = scanner.nextLine();
        System.out.println("User Name:");
        String userName = scanner.nextLine();
        System.out.println("Password");
        String password = scanner.nextLine();

        Entry e = getAccountHelper(accountName);
        if (e != null && !(e.getDomain().equals(accountName) && e.getUser().equals(userName))) {
            System.out.println("USER ACCOUNT ALREADY EXISTS");
            return;
        }
        entryList.put(Utils.paddString(accountName), new Entry(accountName, userName, password));
    }

    /**
     * Helper method that calls EntryList hashMap for the given account
     *
     * @param account Account is the domain name
     * @return Entry that was found or null
     * @see Entry
     */
    private static Entry getAccountHelper(String account) {
        return entryList.get(Utils.paddString(account));
    }

    /**
     * Deletes an account from EntryList
     */
    private static void deleteAccount() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter Account Name to Delete:");
        String account = scanner.nextLine();
        Entry entry = getAccountHelper(account);
        if (entry == null) {
            System.out.println("USER ACCOUNT DOES NOT EXIST!");
            return;
        }
        entryList.remove(Utils.paddString(account));
        System.out.println("Entry Deleted");
    }

    /**
     * Gets the account and prints out user name and password.
     * Only works if there aren't repeat domains.
     */
    private static void getAccount() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter Account Name:");
        String account = scanner.nextLine();
        Entry entry = getAccountHelper(account);
        if (entry == null) {
            System.out.println("USER ACCOUNT DOES NOT EXIST!");
            return;
        }
        System.out.println("username " + Utils.removePadd(entry.getUser()) + " " + "password " + Utils.removePadd(entry.getPassword()));
    }


    private static void changeAccount() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter Account Name:");
        String account = scanner.nextLine();
        Entry entry = getAccountHelper(account);
        if (entry == null) {
            System.out.println("USER ACCOUNT DOES NOT EXIST!");
            return;
        }
        System.out.println("Enter Username for Account:");
        String userName = scanner.nextLine();
        System.out.println("Enter Old Password for Account:");
        String oldPassword = scanner.nextLine();
        System.out.println("Enter New Password for Account:");
        String newPassword = scanner.nextLine();

        entryList.replace(Utils.paddString(account), new Entry(account, userName, newPassword));
    }

    private static void printEntryList() {
        //Debug used for seeing the whole file todo
        for (String mapKey : entryList.keySet()) {
            System.out.println(entryList.get(mapKey));
        }
    }

    /**
     * Inner class representing the Entries of the password manager
     */
    private static class Entry {
        private String domain;
        private String user;
        private String password;

        //Constructor used for new Entry
        private Entry(String domain, String user, String password) {
            this.domain = Utils.paddString(domain);
            this.user = Utils.paddString(user);
            this.password = Utils.paddString(password);
        }

        //Constructor used for read entry
        private Entry(String fullString) {
            this.domain = fullString.substring(0, 80);
            this.user = fullString.substring(80, 160);
            this.password = fullString.substring(160, 240);
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getUser() {
            return user;
        }

        public void setUser(String user) {
            this.user = user;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        /**
         * Returns an entry object with domain user and password each padded to 80 bytes.
         *
         * @return <domain>!!!!!!<user>!!!!!!<password>!!!!!!
         */
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            domain = String.format("%-" + 80 + "s", domain).replace(' ', '!');
            user = String.format("%-" + 80 + "s", user).replace(' ', '!');
            password = String.format("%-" + 80 + "s", password).replace(' ', '!');
            sb.append(domain);
            sb.append(user);
            sb.append(password);
            return sb.toString();
        }


    }
}
