import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;

public class clsEncriptador {
    private static final String FICHERO_TEXTO_ENCRIPTADO = "textoEncriptado.txt";

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        FileOutputStream fos = null;

        //Obtenemos las llaves
        PrivateKey llavePrivadaEmisor = clskeysManager.getClavePrivadaEmisor();
        PublicKey llavePublicaReceptor = clskeysManager.getClavePublicaReceptor();
        //Pedimos el texto a encriptar
        System.out.println("Ingrese el texto a encriptar: ");
        String texto = sc.nextLine();
        //Encriptamos el texto, primero con la llave privada del emisor y luego con la pública del receptor
        byte[] textoEncriptadoPrivateKey = encriptar(texto.getBytes(StandardCharsets.UTF_8), llavePrivadaEmisor, false);
        byte[] textoEncriptadoPublicKey = encriptar(textoEncriptadoPrivateKey, llavePublicaReceptor, true);

        //Ahora lo almacenamos en un fichero
        try {
            //Guardamos el texto encriptado con la llave pública;
            File f = new File(FICHERO_TEXTO_ENCRIPTADO);
            fos = new FileOutputStream(f);
            fos.write(textoEncriptadoPublicKey);

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
        System.out.println("Texto encriptado y almacenado en el fichero " + FICHERO_TEXTO_ENCRIPTADO);
    }

    public static byte[] encriptar(byte[] contenido, Key clave, boolean esPublico) {
        ByteArrayOutputStream bufferSalida = null;
        int tamanoBloque;
        try {
            // Crear objeto Cipher
            Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // Inicializar cifrador en modo cifrado con la clave proporcionada
            cifrador.init(Cipher.ENCRYPT_MODE, clave);

            // Calcular tamaño del bloque
            if (esPublico == true) {
                tamanoBloque = (((RSAPublicKey) clave).getModulus().bitLength() + 7) / 8 - 11;
            } else {
                tamanoBloque = (((RSAPrivateKey) clave).getModulus().bitLength() + 7) / 8 - 11;
            }

            // Inicializar buffer de salida
            bufferSalida = new ByteArrayOutputStream();

            // Cifrar el contenido en bloques
            int offset = 0;
            while (offset < contenido.length) {
                int tamanoBloqueActual = Math.min(tamanoBloque, contenido.length - offset);
                byte[] bloqueCifrado = cifrador.doFinal(contenido, offset, tamanoBloqueActual);
                bufferSalida.write(bloqueCifrado);
                offset += tamanoBloqueActual;
            }
        } catch (NoSuchPaddingException e) {
            System.out.println("Error al encriptar el texto por padding nulo");
        } catch (IllegalBlockSizeException e) {
            System.out.println("Error al encriptar el texto por bloque demasiado grande");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error al encriptar el texto por algoritmo no encontrado");
        } catch (BadPaddingException e) {
            System.out.println("Error al encriptar el texto por padding incorrecto");
        } catch (InvalidKeyException e) {
            System.out.println("Error al encriptar el texto por clave inválida");
        } catch (IOException e) {
            System.out.println("Error al encriptar el texto por entrada/salida");
        }

        // Devolver contenido cifrado completo
        return bufferSalida.toByteArray();
    }
}
