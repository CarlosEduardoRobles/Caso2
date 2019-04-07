package caso2;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

@SuppressWarnings("deprecation")
public class Seguridad {

	// ------------------------------------------------------------
	// ------------------------Atributos---------------------------
	// ------------------------------------------------------------

	/* Atributos que representan los nombres de los algoritmos */
	private String simetrico, asimetrico, hMAC;
	private String padding;
	private SecretKey llave;
	private KeyPair keyPair;
	private X509Certificate certificado;

	// ------------------------------------------------------------
	// --------------------------Métodos---------------------------
	// ------------------------------------------------------------
	public void algoritmosSeleccionados(String[] seleccionados) {
		simetrico = seleccionados[0];
		asimetrico = seleccionados[1];
		hMAC = seleccionados[2];
	}

	public String getSimetrico() {
		return simetrico;
	}

	public String getAsimetrico() {
		return asimetrico;
	}

	public SecretKey getLlave() {
		return llave;
	}

	public void setSimetrico(String simetrico) {
		this.simetrico = simetrico;
	}

	public void setAsimetrico(String asimetrico) {
		this.asimetrico = asimetrico;
	}

	public void setLlave(SecretKey llave) {
		this.llave = llave;
	}

	public void setCertificado(X509Certificate certificado) {
		this.certificado = certificado;
	}

	public void setLlaveSimetrica(byte[] valor) throws Exception {
		byte[] xByte= new byte[16];
		xByte=valor;
		llave = new SecretKeySpec(xByte, simetrico);
	}

	public String getAlgoritmos() {
		return ":" + simetrico + ":" + asimetrico + ":" + hMAC;
	}

	public void setAlgoritmos(String[] algoritmos) {
		simetrico = algoritmos[0];
		asimetrico = algoritmos[1];
		hMAC = algoritmos[2];
	}

	public void setLlaveAsimetrica() throws Exception {
		KeyPairGenerator generador = KeyPairGenerator.getInstance(asimetrico);
		SecureRandom ran = SecureRandom.getInstance("SHA1PRNG");
		generador.initialize(1024, ran);
		keyPair = generador.generateKeyPair();
	}

	public byte[] cifrarSimetrica(byte[] bytes) throws Exception {
		byte[] cipheredText;
		String padding = "";
		if(asimetrico.equals(Cliente.SIMETRICOS[0])){
			System.out.println("Algoritmo: "+Cliente.SIMETRICOS[0]);
		}
		padding = "AES/ECB/PKCS5Padding";
		Cipher cipher = Cipher.getInstance(padding);
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		cipheredText = cipher.doFinal(bytes);
		return cipheredText;
	}

	public byte[] cifrarAsimetrica(String msj) throws Exception {
		Cipher cipher = Cipher.getInstance(asimetrico);
		byte[] bytes = msj.getBytes();
		String original = new String(bytes);
		System.out.println("Clave original: " + original);
		cipher.init(Cipher.ENCRYPT_MODE, certificado.getPublicKey());
		byte[] bytesCifrados = cipher.doFinal(bytes);
		System.out.println("Clave cifrada:" + bytesCifrados);

		return bytesCifrados;
	}

	public String decifrarSimetricamente(byte[] bytesCifrados) throws Exception {
		padding = "AES/ECB/PKCS5Padding";
		Cipher cipher = Cipher.getInstance(padding);
		cipher.init(Cipher.DECRYPT_MODE, llave);
		byte[] cifrado = cipher.doFinal(bytesCifrados);
		String msjOriginal = new String(cifrado);

		return msjOriginal;
	}

	public String decifrarAsimetricamente(byte[] bytesCifrados) throws Exception {
		Cipher cipher = Cipher.getInstance(asimetrico);
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		byte[] bytesOriginal = cipher.doFinal(bytesCifrados);
		String msjOriginal = new String(bytesOriginal);

		return msjOriginal;
	}

	public X509Certificate crearCertificado() throws Exception {
		Date fechaInicio = new Date();
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.DAY_OF_YEAR, 1);
		Date fechaFin = calendar.getTime();             
		BigInteger numeroSerie = new BigInteger(""+Math.abs(SecureRandom.getInstance("SHA1PRNG").nextLong()));  
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal dn = new X500Principal("CN=Test CA Certificate");
		certGen.setSerialNumber(numeroSerie);
		certGen.setIssuerDN(dn);
		certGen.setNotBefore(fechaInicio);
		certGen.setNotAfter(fechaFin);
		certGen.setSubjectDN(dn);                       
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA1withRSA");
		return certGen.generate(keyPair.getPrivate());
	}

	public byte[] getKeyDigest(byte[] buffer) throws Exception {
		Mac mac = Mac.getInstance(hMAC);
		mac.init(llave);
		byte[] bytes = mac.doFinal(buffer);
		return bytes;
	}
}
