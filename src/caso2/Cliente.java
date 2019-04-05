package caso2;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

public class Cliente 
{
	//------------------------------------------------------------
	//-----------------------Constantes---------------------------
	//------------------------------------------------------------
	public static final String HOLA = "HOLA";
	public static final String OK = "OK";
	public static final String AlGORITMOS = "ALGORITMOS";
	public static final String ERROR = "ERROR";
	public static final String SEPARADOR = ":";
	public static final int PUERTO = 1000;
	public static final String[] SIMETRICOS = {"AES","BLOWFISH"};
	public static final String[] ASIMETRICOS = {"RSA"};
	public static final String[] AHMAC = {"HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512"};

	//------------------------------------------------------------
	//------------------------Atributos---------------------------
	//------------------------------------------------------------
	private Socket socketCliente;
	private Scanner sc;
	private BufferedReader reader;
	private PrintWriter writer;
	private Seguridad seguridad;
	
	//------------------------------------------------------------
	//----------------------Constructores-------------------------
	//------------------------------------------------------------
	public Cliente()
	{
		try
		{
			System.out.println("------------Caso 2 - Infraestructura Computacional------------");
			sc = new Scanner(System.in);
			seguridad = new Seguridad();
			socketCliente = new Socket("localhost",PUERTO);
			socketCliente.setKeepAlive(true);
			writer = new PrintWriter(socketCliente.getOutputStream(), true);
			reader = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));			

			procesar();
		}
		catch (Exception e) {e.printStackTrace();}
		
		try 
		{
			reader.close();
			socketCliente.close();
			writer.close();
			sc.close();
		} catch (IOException e) {e.printStackTrace();}
	}
	
	//------------------------------------------------------------
	//--------------------------Metodos---------------------------
	//------------------------------------------------------------	
	public void procesar() throws Exception
	{
 		boolean termino = false;
		boolean esperando = true;
		int estado = 0;
		String respuesta = "";
		String comando = "";
		boolean responde = false;
		byte[] cifra;
		System.out.println("Conexion cliente servidor lograda");
		String entrada = sc.next();
		writer.println(entrada);
		
		while(!termino)
		{
			if(reader.ready())
			{
				esperando = true;
				comando = reader.readLine();
				
				if(comando == null || comando.equals(""))
					continue;
				else if(comando.toLowerCase().contains(ERROR.toLowerCase()) && estado != 5) 
					throw new Exception(comando);
				else if(comando.toLowerCase().contains(OK.toLowerCase())) 
					System.out.println("Servidor: " + comando);

				switch(estado)
				{
				
				case 0:					
					if(comando.equals(OK))
					{
						System.out.println("INICIANDO\n"
								+ "Ingrese 3 algorimtos de cifrado deseados ubicados en la lista y separados por comas.\n"
								+ "Recuerde escoger uno de cada tipo ordenado de la siguiente forma: Simetrico, Asimetrico, HMAC.");
						String[] lista = {"AES", "BLOWFISH", "RSA", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512"};
						
						for (int i = 0; i < lista.length; i++) 						
							System.out.println("		" + (i+1) + "). " + lista[i]);				

						String seleccionados = sc.next();						
						String[] algoritmos = seleccionados.split(","); 
						seguridad.setAlgoritmos(algoritmos);
						respuesta = AlGORITMOS+ seguridad.darAlgoritmos();
						writer.println(respuesta);
						estado++;
					}
					break;
					
				case 1:					
					/*if(comando.equals(OK)) 
					{
						System.out.println("Se intercambiará el Certificado Digital");
						seguridad.setLlaveAsimetrica();
						java.security.cert.X509Certificate certi = seguridad.crearCertificado();
						byte[] bytesCertiPem = certi.getEncoded();
						String certiString = new String(Hex.toHexString(bytesCertiPem));
						String certiFinal = certiString;
						writer.println(certiFinal);
						
						estado++;
					}
					else if(comando.equals(ERROR))
					{
						System.out.println(ERROR);
						esperando = false;
					}*/
					break;
					
				case 2:
					/*if(!comando.equals(OK)) 
					{
					
						System.out.println("Certificado Digital del Servidor");
						System.out.println(comando);
						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
						InputStream in = new ByteArrayInputStream(Hex.decode(comando));
						X509Certificate certiServi = (X509Certificate) certFactory.generateCertificate(in);
						seguridad.setCertificado(certiServi);
						
						System.out.println("CLIENTE: OK");
						writer.println(OK);

						estado++;
					}*/
					break;
					
				case 3:
					/*cifra = Hex.decode(comando);
					String valor = seguridad.decifrarAsimetricamente(cifra);
					seguridad.setLlaveSimetrica(cifra);
					cifra = seguridad.cifrarAsimetrica(valor);
					cifra = Hex.encode(cifra);
					writer.println(new String(cifra));
					
					estado++;*/
					
					break;
				case 4:
					if(comando.equals(OK)) 
					{
						/*System.out.println("Ingrese la consulta");
						String id = sc.nextInt()+"";
						cifra = seguridad.cifrarSimetrica((id).getBytes());
						cifra = Hex.encode(cifra);
						writer.println(cifra);
						System.out.println("Consulta llave simetrica");
						cifra = seguridad.getKeyDigest((id.getBytes()));
						cifra = Hex.encode(cifra);
						writer.println(cifra);
						System.out.println("Consulta HMAC");
						estado++;*/
					}
					
					break;
					
				case 5:
					if(comando.contains(OK)) 
					{
						System.out.println("Servidor: "+comando.split(":")[1]);
					}
					else
						System.out.println("Hubo un error al realizar la consulta: "+comando);
					/*
					if(!responde)
					{
						byte[] llave = Hex.decode(comando);
						respuesta = seguridad.decifrarAsimetricamente(llave);
						seguridad.setLlaveSimetrica(respuesta.getBytes());
						System.out.println("Ingrese usuario");
						String usuario = sc.next();
						System.out.println("Ingrese clave");
						String clave =sc.next();
						String respuestaUs = usuario +","+clave;
						cifra = seguridad.cifrarSimetrica(respuestaUs.getBytes());
						String send = DatatypeConverter.printHexBinary(cifra);
						respuesta = Hex.toHexString(cifra);
						writer.println(send);

						estado++;
						responde = false;
					}	
					comando = seguridad.decifrarSimetricamente(Hex.decode(comando));*/
					
				case 6:
					/*comando = seguridad.decifrarSimetricamente(Hex.decode(comando));
					if(!responde&&comando.equals(OK)) {
						termino = true;
						break;
					}
					else
						throw new Exception ("Ocurrio un error");
				default: 
					estado = 0;*/
					break;
					
				}
			}
			else
			{
				if(esperando)
				{
					System.out.println("esperando...");
					esperando = false;
				}
			}
		}

	}

	public static void main(String[] args) 
	{
		new Cliente();
	}
}
