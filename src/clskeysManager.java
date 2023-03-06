import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class clskeysManager {
    //Rutas de los ficheros de las claves
    private static final String FICHERO_CLAVE_PUBLICA = "src\\public.key";
    private static final String FICHERO_CLAVE_PRIVADA = "src\\private.key";
    private static final String FICHERO_CLAVE_PUBLICA_RECEPTOR = "src\\publicReceptor.key";
    private static final String FICHERO_CLAVE_PRIVADA_RECEPTOR = "src\\privateReceptor.key";

    public static void main(String[] args) {
        //Genera el par de claves
        generarClaves();
        System.out.println("Claves generadas");
    }


    /**
     * Genera un par de claves RSA y las guarda en ficheros
     */
    public static void generarClaves() {
        KeyPair keyEmisor = null;
        KeyPair keyReceptor = null;
        FileOutputStream fos = null;

        //Genera los dos pares de claves
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            keyEmisor = keyGen.generateKeyPair();
            keyReceptor = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe el algoritmo de generación de claves");
        }

        try {
            //Guarda la clave publica en un fichero
            File f = new File(FICHERO_CLAVE_PUBLICA);
            fos = new FileOutputStream(f);
            fos.write(keyEmisor.getPublic().getEncoded());

            //Guarda la clave privada en un fichero
            f = new File(FICHERO_CLAVE_PRIVADA);
            fos = new FileOutputStream(f);
            fos.write(keyEmisor.getPrivate().getEncoded());

            //Guarda la clave pública del receptor en un fichero
            f = new File(FICHERO_CLAVE_PUBLICA_RECEPTOR);
            fos = new FileOutputStream(f);
            fos.write(keyReceptor.getPublic().getEncoded());

            //Guarda la clave privada del receptor en un fichero
            f = new File(FICHERO_CLAVE_PRIVADA_RECEPTOR);
            fos = new FileOutputStream(f);
            fos.write(keyReceptor.getPrivate().getEncoded());

        } catch (FileNotFoundException e) {
            System.out.println("No se ha encontrado el fichero");
        } catch (IOException e) {
            System.out.println("Error al escribir en el fichero");
        } finally {
            try {
                fos.close();

            } catch (IOException e) {
                System.out.println("Error al cerrar el fichero");
            }
        }
    }

    /**
     * Lee la clave publica del fichero
     *
     * @return clave publica
     */
    public static PublicKey getClavePublicaEmisor() {
        File f = new File(FICHERO_CLAVE_PUBLICA);
        PublicKey clavePublica = null;

        //Lee la clave publica del fichero
        try {
            byte[] bytesClavePublica = Files.readAllBytes(f.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytesClavePublica);
            clavePublica = keyFactory.generatePublic(publicKeySpec);
        } catch (IOException e) {
            System.out.println("Error al leer el fichero");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe el algoritmo de generación de claves");
        } catch (InvalidKeySpecException e) {
            System.out.println("Clave publica invalida");
        }
        return clavePublica;
    }

    /**
     * Lee la clave privada del fichero
     *
     * @return clave privada
     */
    public static PrivateKey getClavePrivadaEmisor() {
        File f = new File(FICHERO_CLAVE_PRIVADA);
        PrivateKey clavePrivada = null;

        //Lee la clave privada del fichero
        try {
            byte[] bytesClavePrivada = Files.readAllBytes(f.toPath());
            EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bytesClavePrivada);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            clavePrivada = keyFactory.generatePrivate(clavePrivadaSpec);
        } catch (IOException e) {
            System.out.println("Error al leer el fichero");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe el algoritmo de generación de claves");
        } catch (InvalidKeySpecException e) {
            System.out.println("Clave privada invalida");
        }
        return clavePrivada;
    }

    /**
     * Lee la clave publica del fichero
     *
     * @return clave publica
     */
    public static PublicKey getClavePublicaReceptor() {
        File f = new File(FICHERO_CLAVE_PUBLICA_RECEPTOR);
        PublicKey clavePublica = null;

        //Lee la clave publica del fichero
        try {
            byte[] bytesClavePublica = Files.readAllBytes(f.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytesClavePublica);
            clavePublica = keyFactory.generatePublic(publicKeySpec);
        } catch (IOException e) {
            System.out.println("Error al leer el fichero");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe el algoritmo de generación de claves");
        } catch (InvalidKeySpecException e) {
            System.out.println("Clave publica invalida");
        }
        return clavePublica;
    }

    /**
     * Lee la clave privada del fichero
     *
     * @return clave privada
     */
    public static PrivateKey getClavePrivadaReceptor() {
        File f = new File(FICHERO_CLAVE_PRIVADA_RECEPTOR);
        PrivateKey clavePrivada = null;

        //Lee la clave privada del fichero
        try {
            byte[] bytesClavePrivada = Files.readAllBytes(f.toPath());
            EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bytesClavePrivada);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            clavePrivada = keyFactory.generatePrivate(clavePrivadaSpec);
        } catch (IOException e) {
            System.out.println("Error al leer el fichero");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe el algoritmo de generación de claves");
        } catch (InvalidKeySpecException e) {
            System.out.println("Clave privada invalida");
        }
        return clavePrivada;
    }

}
