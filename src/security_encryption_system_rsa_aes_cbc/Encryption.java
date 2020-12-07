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
			System.out.println("| 加密完畢                                             \t|");
			System.out.println("| 密文檔案已儲存於 text 資料夾中的 cipher.txt 檔案        \t|");
			System.out.println("| AES金鑰加密檔已儲存於 text 資料夾中的 aes_key.txt 檔案  \t|");
			System.out.println("| -> 輸入 1 可返回主頁面                                \t|");
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

//		System.out.println("[資訊] 編碼前的 AES 金鑰: " + new String(aes_key_encrypted));
//		String en = Base64.getEncoder().encodeToString(aes_key_encrypted);
//		byte[] de = Base64.getDecoder().decode(en);
//		System.out.println("[資訊] 編碼後的 AES 金鑰: " + en);
//		System.out.println("[資訊] 編碼後的 AES 金鑰: " + new String(de));
//
//		Path path = Paths.get(aes_key_encrypted_file);
//		String key_file = Files.readString(path);
//		byte[] aes_key = Base64.getDecoder().decode(key_file);
//		System.out.println("[資訊] 編碼後的 AES 金鑰: " + new String(aes_key));

		System.out.println("[狀態] AES 金鑰加密檔儲存完成");
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
		System.out.println("[狀態] 密文儲存完成");
	}

	/*
	 * step 5: encrypt AES key use RSA public key
	 */
	private static void encrypt_aes_key() throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, rsa_public_key);
		aes_key_encrypted = cipher.doFinal(aes_key);
		// System.out.println("[資訊] 加密前的 AES 金鑰: " + new String(aes_key));
		// System.out.println("[資訊] 加密後的 AES 金鑰: " + new String(aes_key_encrypted));
		System.out.println("[狀態] AES 金鑰加密完成");
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
			System.out.println("| 加密程式執行中                        \t|");
			System.out.println("| 請將要加密的檔案放置於 text 資料夾中，   \t|");
			System.out.println("| 並將檔案名稱命名為 input.txt，         \t|");
			System.out.println("| 放置完畢                             \t|");
			System.out.println("| -> 輸入 1 繼續執行程式                \t|");
			System.out.println("| -> 輸入 2 可返回上一步                \t|");
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
				// System.out.println("[資訊] 讀取的 input.txt 檔案內容");
				// System.out.print(input_data);
				// System.out.println("[資訊] 結束讀取");
			} finally {
				br.close();
			}
		} catch (FileNotFoundException error) {
			// System.out.println("[錯誤]" + error);
			System.out.println("[錯誤] input.txt 檔案不存在，請重新放置後再繼續執行程式");
			return false;
		} catch (Exception error) {
			System.out.println("[錯誤] 程式發生未預期的錯誤" + error);
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

		// System.out.println("[資訊] AES金鑰: " + aes_key.toString());
		System.out.println("[狀態] 成功產生 AES 金鑰");
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

			System.out.println("[狀態] 成功載入 RSA 2048 公鑰");

		} catch (NoSuchFileException error) {
			// System.out.println("[錯誤]" + error);
			System.out.println("[錯誤] RSA 公鑰不存在，請執行 Decryption 程式產生 RSA 金鑰");
			return false;
		} catch (Exception error) {
			System.out.println("[錯誤] 程式發生未預期的錯誤" + error);
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
			// System.out.println("[錯誤] 無法清除 console 的內容 " + error);
		}
	}

	private static void close_program() {
		System.out.println("[狀態] 結束程式");
		scanner.close();
		System.exit(0);
	}

	private static void show_welcome_msg() {
		clear_console();
		System.out.println("|+++++++++++++++++++++++++++++++++++++++|");
		System.out.println("| 歡迎使用 Linwebs RSA + AES-CBC 加密系統 \t|");
		System.out.println("| -> 輸入 1 執行加密程式                  \t|");
		System.out.println("| -> 輸入 2 離開程式                     \t|");
		System.out.println("| 註: 如需解密請執行 Decryption 程式      \t|");
		System.out.println("|+++++++++++++++++++++++++++++++++++++++|");
	}
}
