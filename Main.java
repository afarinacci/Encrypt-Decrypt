package encryptdecrypt;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.File;

public class Main {

    public static String readFileAsString(String fileName) throws IOException {
        return new String(Files.readAllBytes(Paths.get(fileName)));
    }
    public static void main(String[] args) {
        int key = 0;
        String data = "";
        String in = "";
        String out = "";
        String mode = "enc";
        String alg = "shift";
        for (int i = 0; i < args.length; i++) {
            if ("-key".equals(args[i])) {
                key = Integer.parseInt(args[i+1]);
            } else if ("-data".equals(args[i])) {
                data = args[i+1];
            } else if ("-in".equals(args[i])) {
                in = args[i+1];
            } else if ("-out".equals(args[i])) {
                out = args[i+1];
            } else if ("-mode".equals(args[i])) {
                mode = args[i+1];
            } else if ("-alg".equals(args[i])) {
                alg = args[i+1];
            }
        }

        // read data from args or file
        String encDecString = "";
        if ( !in.isEmpty() && data.isEmpty() ) {
            String pathToFile = in;
            try {
                String fileContents = readFileAsString(pathToFile);
                encDecString = fileContents;
            } catch (IOException e) {
                System.out.println("Error, Cannot read file: " + e.getMessage());
            }
        } else {
            encDecString = data;
        }

        // Encrypt or decrypt the data
        Encryptor encryptor;
        if ("unicode".equals(alg)) {
            encryptor = new Encryptor(new UnicodeEncryptionStrategy());
        } else {
            encryptor = new Encryptor(new ShiftEncryptionStrategy());
        }
        String output = encryptor.encOrDec(mode, key, encDecString);

        // print or send results to file
        if (out.isEmpty()) {
            System.out.println(output);
        } else {
            //write to file
            File file = new File(out);
            try (FileWriter writer = new FileWriter(file)) {     // it will close the writer automatically.
                writer.write(output);
            } catch (IOException e) {
                System.out.printf("Error, An exception occurs %s", e.getMessage());
            }
        }
    }
}
interface EncryptionStrategy {

    String encrypt(String data, int key);

    String decrypt(String data, int key);
}
class ShiftEncryptionStrategy implements EncryptionStrategy {
    @Override
    public String encrypt(String data, int key) {
        char[] chars = data.toCharArray();
        for (int i = 0; i < chars.length ; i++) {
            int unicode = (int) chars[i];
            if (unicode >= 97 && unicode <= 122) {
                int newUnicode = unicode + key;
                if (newUnicode > 122) {
                    int dif = newUnicode - 122;
                    newUnicode = 97 - 1 + dif;
                }
                chars[i] = (char) newUnicode;
            }
        }
        String output = new String(chars);
        return output;
    }
    @Override
    public String decrypt(String data, int key) {
        char[] chars = data.toCharArray();
        for (int i = 0; i < chars.length ; i++) {
            int unicode = (int) chars[i];
            if (unicode >= 97 && unicode <= 122) {
                int newUnicode = unicode - key;
                if (newUnicode < 97) {
                    int dif = 97 - newUnicode;
                    newUnicode = 122 + 1 - dif;
                }
                chars[i] = (char) newUnicode;
            }
        }
        String output = new String(chars);
        return output;
    }
}
class UnicodeEncryptionStrategy implements EncryptionStrategy {
    @Override
    public String encrypt(String data, int key) {
        char[] chars = data.toCharArray();
        for (int i = 0; i < chars.length ; i++) {
            int unicode = (int) chars[i];
            if (unicode >= 32 && unicode <= 127) {
                int newUnicode = unicode + key;
                if (newUnicode > 127) {
                    int dif = newUnicode - 127;
                    newUnicode = 32 - 1 + dif;
                }
                chars[i] = (char) newUnicode;
            }
        }
        String output = new String(chars);
        return output;
    }
    @Override
    public String decrypt(String data, int key) {
        char[] chars = data.toCharArray();
        for (int i = 0; i < chars.length ; i++) {
            int unicode = (int) chars[i];
            if (unicode >= 32 && unicode <= 127) {
                int newUnicode = unicode - key;
                if (newUnicode < 32) {
                    int dif = 32 - newUnicode;
                    newUnicode = 127 + 1 - dif;
                }
                chars[i] = (char) newUnicode;
            }
        }
        String output = new String(chars);
        return output;
    }
}
class Encryptor {
    EncryptionStrategy encryptionStrategy;
    public Encryptor(EncryptionStrategy encryptionStrategy) {
        this.encryptionStrategy = encryptionStrategy;
    }
    String encOrDec(String mode, int key, String data) {
        return "dec".equals(mode) ? this.encryptionStrategy.decrypt(data, key)
                : this.encryptionStrategy.encrypt(data, key);
    }
}