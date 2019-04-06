package caso2;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.management.remote.SubjectDelegationPermission;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.*;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

public class Seguridad 
{
	//------------------------------------------------------------
	//-----------------------Constantes---------------------------
	//------------------------------------------------------------
	public final static String PADDING = "/ECB/PKCS5Padding";

	//------------------------------------------------------------
	//------------------------Atributos---------------------------
	//------------------------------------------------------------
	private String padding /*Padding a insertar*/, 
		simetrico /*Nombre del algoritmo simetrico escogido*/, 
		asimetrico /*Nombre del algoritmo asimetrico escogido*/, 
		hMAC /*Nombre del algoritmo HMAC escogido*/;
	
	private SecretKey llave;	
	private KeyPair keyPair;
	private X509v3CertificateBuilder certificado;	
	
	//------------------------------------------------------------
	//--------------------------Metodos---------------------------
	//------------------------------------------------------------	
	public void algoritmosSeleccionados(String[] seleccionados)
	{
		simetrico = seleccionados[0];
		asimetrico = seleccionados[1];
		hMAC = seleccionados[2];
	}
	
	public String getSimetrico() {return simetrico;}

	public String getAsimetrico() {return asimetrico;}

	public SecretKey getLlave() {return llave;}

	public void setSimetrico(String simetrico) {this.simetrico = simetrico;}

	public void setAsimetrico(String asimetrico) {this.asimetrico = asimetrico;}

	public void setLlave(SecretKey llave) {this.llave = llave;}

	public void setCertificado(X509v3CertificateBuilder certificado) {this.certificado = certificado;}

	public void setLlaveSimetrica(byte[] valor) throws Exception {llave = new SecretKeySpec(valor, simetrico);}
	
	public String darAlgoritmos() {return ":"+simetrico+":"+asimetrico+":"+hMAC;}
	
	public void setAlgoritmos(String[] algoritmos)
	{
		simetrico = algoritmos[0];
		asimetrico = algoritmos[1];
		hMAC = algoritmos[2];
	}
	
	public void setLlaveAsimetrica() throws Exception
	{
		//TODO Que es SHA1PRNG
		KeyPairGenerator generador = KeyPairGenerator.getInstance(asimetrico);
		SecureRandom ran = SecureRandom.getInstance("SHA1PRNG");
		generador.initialize(1024,ran);
		keyPair = generador.generateKeyPair();
	}
	
	public byte[] cifrarSimetrica(byte[] bytes) throws Exception
	{
		//TODO Renombrar X y Y. Como? Aun no se :v
		System.out.println("Algoritmo simetrico escogido: "+ Cliente.SIMETRICOS[0]);
		padding = simetrico + PADDING;
		Cipher cipher = Cipher.getInstance(padding);
		byte[] x = new byte[16];
		byte[] y = llave.getEncoded();
		y = x;
		SecretKeySpec secretKeySpec = new SecretKeySpec(y, simetrico);
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		
		return cipher.doFinal(bytes);
	}

	public byte[] cifrarAsimetrica(String msj) throws Exception
	{
		Cipher cipher = Cipher.getInstance(asimetrico);
		byte[] bytes = msj.getBytes();
		String original = new String(bytes);
		System.out.println("Clave original: "+ original);
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		byte[] bytesCifrados = cipher.doFinal(bytes);
		System.out.println("Clave cifrada:"+ bytesCifrados);
		
		return bytesCifrados;	
	}

	public String decifrarSimetricamente(byte[] bytesCifrados) throws Exception
	{
		padding = simetrico + PADDING;
		Cipher cipher = Cipher.getInstance(padding);
		cipher.init(Cipher.DECRYPT_MODE, llave);
		byte[] cifrado = cipher.doFinal(bytesCifrados);
		String msjOriginal = new String(cifrado);
		
		return msjOriginal;
	}

	public String decifrarAsimetricamente(byte[] bytesCifrados) throws Exception
	{
		Cipher cipher = Cipher.getInstance(asimetrico);
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		byte[] bytesOriginal = cipher.doFinal(bytesCifrados);
		String msjOriginal = new String(bytesOriginal);
		
		return msjOriginal;
	}

	@SuppressWarnings("deprecation")
	public X509v3CertificateBuilder crearCertificado() throws Exception
	{
		Date notBefore  = new Date();
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.DAY_OF_YEAR, 1);
		Date notAfter  = calendar.getTime();             
		BigInteger serial = new BigInteger(""+Math.abs(SecureRandom.getInstance("SHA1PRNG").nextLong())); 
		//TODO Crear el certificado con la informacion pedida
		X500Name issuer = new X500Name("CN=Covata");
		X500Name subject = new X500Name("CN=Delta");
		byte[] encoded = keyPair.getPublic().getEncoded();
		SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
		    ASN1Sequence.getInstance(encoded));
		X509v3CertificateBuilder certificado = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPublicKeyInfo);
		return certificado;
	}

	public byte[] getKeyDigest(byte[] buffer) throws Exception
	{
		//TODO Revisar esto
		try 
		{
			System.out.println("Algoritmo:"+ hMAC);
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(buffer);
			
			return messageDigest.digest();
		} 
		catch (Exception e) {return null;}
	}
	
	public byte[] calcularHash(String mensaje) 
	{
		try
		{
			String msj = mensaje;
			byte[] text = msj.getBytes();
			byte [] digest = getKeyDigest(text);
			
			return digest;
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
}
