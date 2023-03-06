import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class clsDesencriptador {
    private static final String FICHERO_TEXTO_ENCRIPTADO = "textoEncriptado.txt";

    public static void main(String[] args) {
        //Obtenemos las llaves
        PrivateKey llavePrivadaReceptor = clskeysManager.getClavePrivadaEmisor();
        PublicKey llavePublicaEmisor = clskeysManager.getClavePublicaEmisor();
        //Desencriptamos el texto, primero con la llave privada del receptor y luego con la pública del emisor
        String textoDesencriptado = desencriptar(FICHERO_TEXTO_ENCRIPTADO, llavePublicaEmisor, llavePrivadaReceptor);
        //Mostramos el texto desencriptado
        System.out.println("Texto desencriptado: " + textoDesencriptado);
    }

    public static String desencriptar(String rutaFicero, PublicKey llavePublicaEmisor, PrivateKey llavePrivadaReceptor) {
        byte[] textoDesencriptado = null;
        String textoFinal = null;
        ByteArrayOutputStream bufferSalida = null;
        try {
            // Se obtiene un cifrador RSA
            Cipher descifradorPublicoEmisor = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            Cipher descifradorPrivadoReceptor = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            //Leemos el fichero
            File f = new File(rutaFicero);
            byte[] textoEncriptado = leerArchivo(f);

            // Inicializar buffer de salida
            bufferSalida = new ByteArrayOutputStream();

            //Desencriptamos el texto con la llave privada del receptor
            descifradorPrivadoReceptor.init(Cipher.DECRYPT_MODE, llavePrivadaReceptor);
            int tamanoBloquePrivado = (((RSAPrivateKey) llavePrivadaReceptor).getModulus().bitLength() + 7) / 8 - 11;
            //byte[] textoDesencriptadoConPublica = descifradorPrivadoReceptor.doFinal(textoEncriptado);
            // Descifrar el contenido en bloques
            int offset = 0;
            while (offset < textoEncriptado.length) {
                int tamanoBloqueActual = Math.min(tamanoBloquePrivado, textoEncriptado.length - offset);
                byte[] bloqueCifrado = descifradorPrivadoReceptor.doFinal(textoEncriptado, offset, tamanoBloqueActual);
                bufferSalida.write(bloqueCifrado);
                offset += tamanoBloqueActual;
            }

            //Desencriptamos el texto con la pública del emisor
            descifradorPublicoEmisor.init(Cipher.DECRYPT_MODE, llavePublicaEmisor);
            int tamanoBloquePublico = (((RSAPublicKey) llavePublicaEmisor).getModulus().bitLength() + 7) / 8 - 11;
            //textoDesencriptado = descifradorPublicoEmisor.doFinal(textoDesencriptadoConPublica);

            offset = 0;
            while (offset < textoEncriptado.length) {
                int tamanoBloqueActual = Math.min(tamanoBloquePublico, textoEncriptado.length - offset);
                byte[] bloqueCifrado = descifradorPublicoEmisor.doFinal(textoEncriptado, offset, tamanoBloqueActual);
                bufferSalida.write(bloqueCifrado);
                offset += tamanoBloqueActual;
            }

            //textoFinal = new String(textoDesencriptado);
        } catch (NoSuchPaddingException e) {
            System.out.println("Error por padding nulo");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("El algoritmo no existe");
        } catch (InvalidKeyException e) {
            System.out.println("La llave no es válida");
        } catch (BadPaddingException e) {
            System.out.println("Error por padding incorrecto"+e);
        } catch (IllegalBlockSizeException e) {
            System.out.println("Error al desencriptar por tamaño de bloque incorrecto");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] contenidoDesencriptado = bufferSalida.toByteArray();
        try {
            textoFinal = new String(contenidoDesencriptado, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return textoFinal;
    }

    public static byte[] leerArchivo(File archivo) {
        byte[] contenido = null;
        try {
            contenido = Files.readAllBytes(archivo.toPath());
        } catch (IOException e) {
            System.out.println("Error al leer el archivo");
        }
        return contenido;
    }


}
