/*
 * Linwebs 2020.12
 * NCYU Information Security and Management
 * RSA + AES-CBC Encryption System
 * Needed: Java8 or newer version
 */

package security_encryption_system_rsa_aes_cbc;

import java.io.*;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
	private static String key_file_path = "key/";
	private static String data_file_path = "text/";
	private static String rsa_key_file = key_file_path + "rsa_key";
	private static String data_file = data_file_path + "input.txt";
	private static String cipher_file = data_file_path + "cipher.txt";
	private static String aes_key_encrypted_file = data_file_path + "aes_key.txt";
	private static PublicKey rsa_public_key;
	private static byte[] aes_key;
	private static byte[] aes_key_encrypted;
	private static Scanner scanner;
	private static String input_data;
	private static byte[] cipher_iv;

	public static void main(String[] args) throws Exception {
		scanner = new Scanner(System.in);
		running_window();
	}

	private static void running_window() throws Exception {
		String status = "";
		while (!status.equals("1")) {
			show_welcome_msg();
			status = scanner.next();

			if (status.equals("1")) {
				// step 1: load RSA public key
				if (!load_rsa_public_key()) {
					close_program();
				}
				// step 2: generate AES key
				generate_aes_key();
				// step 3: input data
				if (!input_data_msg()) {
					status = "";
					continue;
				}
				if (!read_data()) {
					// no file
					status = "";
					continue;
				}
				// step 4: encrypt data using AES key
				encrypt_data();
				// step 5: encrypt AES key use RSA public key
				encrypt_aes_key();
				// step 6: save cipher data to file
				save_cipher();
				// step 7: save encrypted AES key to file
				save_encrypted_aes_key();
				// finish
				if (finish_encrypt()) {
					status = "";
					continue;
				}
			} else if (status.equals("2")) {
				close_program();
			}
		}
	}

	private static boolean finish_encrypt() {
		String status = "";
		while (!status.equals("1")) {
			System.out.println("|+++++++++++++++++++++++++++++++++++++++++++++++++++++++|");
			System.out.println("| �[�K����                                             \t|");
			System.out.println("| �K���ɮפw�x�s�� text ��Ƨ����� cipher.txt �ɮ�        \t|");
			System.out.println("| AES���_�[�K�ɤw�x�s�� text ��Ƨ����� aes_key.txt �ɮ�  \t|");
			System.out.println("| -> ��J 1 �i��^�D����                                \t|");
			System.out.println("|+++++++++++++++++++++++++++++++++++++++++++++++++++++++|");
			status = scanner.next();
			if (status.equals("1")) {
				return true;
			}
		}
		return false;
	}

	/*
	 * step 7: save encrypted AES key to file
	 */
	private static void save_encrypted_aes_key() throws Exception {
		File file_path = new File(data_file_path);
		if (!file_path.exists()) {
			file_path.mkdir();
		}

		FileWriter out_cipher = new FileWriter(aes_key_encrypted_file);
		out_cipher.write(Base64.getEncoder().encodeToString(aes_key_encrypted));
		out_cipher.close();

//		System.out.println("[��T] �s�X�e�� AES ���_: " + new String(aes_key_encrypted));
//		String en = Base64.getEncoder().encodeToString(aes_key_encrypted);
//		byte[] de = Base64.getDecoder().decode(en);
//		System.out.println("[��T] �s�X�᪺ AES ���_: " + en);
//		System.out.println("[��T] �s�X�᪺ AES ���_: " + new String(de));
//
//		Path path = Paths.get(aes_key_encrypted_file);
//		String key_file = Files.readString(path);
//		byte[] aes_key = Base64.getDecoder().decode(key_file);
//		System.out.println("[��T] �s�X�᪺ AES ���_: " + new String(aes_key));

		System.out.println("[���A] AES ���_�[�K���x�s����");
	}

	/*
	 * step 6: save cipher data to file
	 */
	private static void save_cipher() throws Exception {
		// cipher_iv
		File file_path = new File(data_file_path);
		if (!file_path.exists()) {
			file_path.mkdir();
		}

		FileWriter out_cipher = new FileWriter(cipher_file);
		out_cipher.write(Base64.getEncoder().encodeToString(cipher_iv));
		out_cipher.close();
		System.out.println("[���A] �K���x�s����");
	}

	/*
	 * step 5: encrypt AES key use RSA public key
	 */
	private static void encrypt_aes_key() throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, rsa_public_key);
		aes_key_encrypted = cipher.doFinal(aes_key);
		// System.out.println("[��T] �[�K�e�� AES ���_: " + new String(aes_key));
		// System.out.println("[��T] �[�K�᪺ AES ���_: " + new String(aes_key_encrypted));
		System.out.println("[���A] AES ���_�[�K����");
	}

	/*
	 * step 4: encrypt data using AES key
	 */
	private static void encrypt_data() throws Exception {
		byte[] input_bytes = input_data.getBytes();

		// generate initial vector
		int iv_size = 16;
		byte[] iv = new byte[iv_size];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		IvParameterSpec ivps = new IvParameterSpec(iv);

		// convert aes key bytes to SecretKeySpec type
		SecretKeySpec key = new SecretKeySpec(aes_key, "AES");

		// encrypt
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivps);
		byte[] encrypted = cipher.doFinal(input_bytes);

		// combine initial vector and cipher
		cipher_iv = new byte[iv_size + encrypted.length];
		System.arraycopy(iv, 0, cipher_iv, 0, iv_size);
		System.arraycopy(encrypted, 0, cipher_iv, iv_size, encrypted.length);
	}

	/*
	 * step 3: input data
	 */
	private static boolean input_data_msg() {
		String status = "";
		while (!status.equals("1")) {
			clear_console();

			File file_path = new File(data_file_path);
			if (!file_path.exists()) {
				file_path.mkdir();
			}
			System.out.println("|+++++++++++++++++++++++++++++++++++++++|");
			System.out.println("| �[�K�{�����椤                        \t|");
			System.out.println("| �бN�n�[�K���ɮש�m�� text ��Ƨ����A   \t|");
			System.out.println("| �ñN�ɮצW�٩R�W�� input.txt�A         \t|");
			System.out.println("| ��m����                             \t|");
			System.out.println("| -> ��J 1 �~�����{��                \t|");
			System.out.println("| -> ��J 2 �i��^�W�@�B                \t|");
			System.out.println("|+++++++++++++++++++++++++++++++++++++++|");
			status = scanner.next();
			if (status.equals("1")) {
				return true;
			} else if (status.equals("2")) {
				return false;
			}
		}
		return false;
	}

	/*
	 * step 3: input data
	 */
	private static boolean read_data() throws FileNotFoundException {
		try {
			InputStreamReader isr = new InputStreamReader(new FileInputStream(data_file), "UTF-8");
			BufferedReader br = new BufferedReader(isr);

			try {
				StringBuilder sb = new StringBuilder();
				String line = br.readLine();

				while (line != null) {
					sb.append(line);
					sb.append(System.lineSeparator());
					line = br.readLine();
				}
				input_data = sb.toString();
				// System.out.println("[��T] Ū���� input.txt �ɮפ��e");
				// System.out.print(input_data);
				// System.out.println("[��T] ����Ū��");
			} finally {
				br.close();
			}
		} catch (FileNotFoundException error) {
			// System.out.println("[���~]" + error);
			System.out.println("[���~] input.txt �ɮפ��s�b�A�Э��s��m��A�~�����{��");
			return false;
		} catch (Exception error) {
			System.out.println("[���~] �{���o�ͥ��w�������~" + error);
			return false;
		}
		return true;
	}

	/*
	 * step 2: generate AES key
	 */
	private static void generate_aes_key() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey key = keyGen.generateKey();

		// hash generated aes_key using SHA-256
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(key.getEncoded());
		aes_key = new byte[16];
		System.arraycopy(digest.digest(), 0, aes_key, 0, aes_key.length);

		// System.out.println("[��T] AES���_: " + aes_key.toString());
		System.out.println("[���A] ���\���� AES ���_");
	}

	/*
	 * step 1: load RSA public key
	 */
	private static boolean load_rsa_public_key() {
		try {
			// read RSA key from file
			Path path = Paths.get(rsa_key_file + ".pub");
			String key_file = new String(Files.readAllBytes(path), "utf-8");

			String public_key_pem = key_file.replace("-----BEGIN RSA PUBLIC KEY-----", "").replaceAll("\n", "")
					.replace("-----END RSA PUBLIC KEY-----", "");
			// System.out.println(public_key_pem); // Output public key

			byte[] bytes = Base64.getUrlDecoder().decode(public_key_pem);

			/* generate RSA public key */
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
			rsa_public_key = kf.generatePublic(ks);

			System.out.println("[���A] ���\���J RSA 2048 ���_");

		} catch (NoSuchFileException error) {
			// System.out.println("[���~]" + error);
			System.out.println("[���~] RSA ���_���s�b�A�а��� Decryption �{������ RSA ���_");
			return false;
		} catch (Exception error) {
			System.out.println("[���~] �{���o�ͥ��w�������~" + error);
			return false;
		}
		return true;
	}

	private static void clear_console() {
		try {
			String os = System.getProperty("os.name");

			if (os.contains("Windows")) {
				Runtime.getRuntime().exec("cls");
			} else {
				Runtime.getRuntime().exec("clear");
			}
		} catch (Exception error) {
			// System.out.println("[���~] �L�k�M�� console �����e " + error);
		}
	}

	private static void close_program() {
		System.out.println("[���A] �����{��");
		scanner.close();
		System.exit(0);
	}

	private static void show_welcome_msg() {
		clear_console();
		System.out.println("|+++++++++++++++++++++++++++++++++++++++|");
		System.out.println("| �w��ϥ� Linwebs RSA + AES-CBC �[�K�t�� \t|");
		System.out.println("| -> ��J 1 ����[�K�{��                  \t|");
		System.out.println("| -> ��J 2 ���}�{��                     \t|");
		System.out.println("| ��: �p�ݸѱK�а��� Decryption �{��      \t|");
		System.out.println("|+++++++++++++++++++++++++++++++++++++++|");
	}
}
