/*
 * Linwebs 2020.12
 * NCYU Information Security and Management
 * RSA + AES-CBC Decryption System
 * Needed: Java8 or newer version
 */

package security_encryption_system_rsa_aes_cbc;

import java.io.*;
import java.nio.file.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Decryption {
	private static String key_file_path = "key/";
	private static String data_file_path = "text/";
	private static String rsa_key_file = key_file_path + "rsa_key";
	private static String cipher_file = data_file_path + "cipher.txt";
	private static String aes_key_encrypted_file = data_file_path + "aes_key.txt";
	private static String data_file = data_file_path + "output.txt";
	private static Scanner scanner;
	private static byte[] cipher_iv;
	private static byte[] aes_key;
	private static byte[] aes_key_encrypted;
	private static PrivateKey rsa_private_key;
	private static String output_data;

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
				// step 1: load cipher from file
				if (!load_cipher()) {
					close_program();
				}
				// step 2: load encrypted AES key from file
				if (!load_aes_key()) {
					close_program();
				}
				// step 3: load RSA private key from file
				if (!load_rsa_private_key()) {
					close_program();
				}
				// step 4: decrypt encrypted AES key using RSA private key
				decrypt_aes_key();
				// step 5: decrypt cipher using AES key
				decrypt_cipher();
				// step 6: save data to file
				save_data();
				// finish
				if (finish_decrypt()) {
					status = "";
					continue;
				}
			} else if (status.equals("2")) {
				genrate_rsa_key();
				finish_genrate_rsa_key();
			} else if (status.equals("3")) {
				close_program();
			}
		}
	}

	private static boolean finish_decrypt() {
		String status = "";
		while (!status.equals("1")) {
			System.out.println("|+++++++++++++++++++++++++++++++++++++++++++++++|");
			System.out.println("| 解密完畢                                      \t|");
			System.out.println("| 原文檔案已儲存於 text 資料夾中的 output.txt 檔案 \t|");
			System.out.println("| -> 輸入 1 可返回主頁面                         \t|");
			System.out.println("|+++++++++++++++++++++++++++++++++++++++++++++++|");
			status = scanner.next();
			if (status.equals("1")) {
				return true;
			}
		}
		return false;
	}

	/*
	 * step 6: save data to file
	 */
	private static void save_data() throws IOException {
		// System.out.println("[資訊] 原文: " + output_data);
		File file_path = new File(data_file_path);
		if (!file_path.exists()) {
			file_path.mkdir();
		}
		
		Writer out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(data_file), "UTF-8"));
		try {
			out.write(output_data);
		} finally {
			out.close();
		}

		System.out.println("[狀態] 原文檔案儲存完成");
	}

	/*
	 * step 5: decrypt cipher using AES key
	 */
	private static void decrypt_cipher() throws Exception {

		// extract initial vector
		int iv_size = 16;
		byte[] iv = new byte[iv_size];
		System.arraycopy(cipher_iv, 0, iv, 0, iv.length);
		IvParameterSpec ivps = new IvParameterSpec(iv);

		// extract encrypted part
		int encrypted_size = cipher_iv.length - iv_size;
		byte[] encrypted_bytes = new byte[encrypted_size];
		System.arraycopy(cipher_iv, iv_size, encrypted_bytes, 0, encrypted_size);

		// hash key
		SecretKeySpec key = new SecretKeySpec(aes_key, "AES");

		// decrypt
		Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ivps);
		byte[] decrypted = cipherDecrypt.doFinal(encrypted_bytes);
		output_data = new String(decrypted);

		System.out.println("[狀態] 密文解密完成");
	}

	/*
	 * step 4: decrypt encrypted AES key using RSA private key
	 */
	private static void decrypt_aes_key() throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, rsa_private_key);
		aes_key = cipher.doFinal(aes_key_encrypted);
		// System.out.println("[資訊] 解密前的 AES 金鑰: " + new String(aes_key_encrypted));
		// System.out.println("[資訊] 解密後的 AES 金鑰: " + new String(aes_key));

		System.out.println("[狀態] AES 金鑰解密完成");
	}

	/*
	 * step 3: load RSA private key from file
	 */
	private static boolean load_rsa_private_key() {
		try {
			File file_path = new File(key_file_path);
			if (!file_path.exists()) {
				System.out.println("[錯誤] key 資料夾不存在，請產生 RSA 金鑰後再執行 Encryption 程式進行加密");
				return false;
			}

			Path path = Paths.get(rsa_key_file + ".key");
			String key_file = Files.readString(path);

			key_file = key_file.replace("-----BEGIN RSA PRIVATE KEY-----", "").replaceAll("\n", "")
					.replace("-----END RSA PRIVATE KEY-----", "");

			byte[] rsa_key_pem = Base64.getUrlDecoder().decode(key_file);

			/* generate RSA private key */

			KeyFactory kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(rsa_key_pem);
			rsa_private_key = kf.generatePrivate(ks);

			System.out.println("[狀態] 成功載入 RSA 2048 私鑰");
		} catch (NoSuchFileException error) {
			// System.out.println("[錯誤]" + error);
			System.out.println("[錯誤] RSA 私鑰不存在，請產生 RSA 金鑰後再執行 Encryption 程式進行加密");
			return false;
		} catch (Exception error) {
			System.out.println("[錯誤] 程式發生未預期的錯誤" + error);
			return false;
		}
		return true;
	}

	/*
	 * step 2: load encrypted AES key from file
	 */
	private static boolean load_aes_key() {
		try {
			// read AES key from file
			Path path = Paths.get(aes_key_encrypted_file);
			String key_file = Files.readString(path);
			// System.out.println("[資訊] 編碼前的 AES 金鑰: " + key_file);

			key_file = key_file.replaceAll("\n", "");

			aes_key_encrypted = Base64.getDecoder().decode(key_file);
			// System.out.println("[資訊] 編碼後的 AES 金鑰: " + new String(aes_key_encrypted));

			System.out.println("[狀態] 成功載入 AES 金鑰加密檔");
		} catch (NoSuchFileException error) {
			// System.out.println("[錯誤]" + error);
			System.out.println("[錯誤] AES 金鑰加密檔 aes_key.txt 不存在，請執行 Encryption 程式進行加密");
			return false;
		} catch (Exception error) {
			System.out.println("[錯誤] 程式發生未預期的錯誤" + error);
			return false;
		}
		return true;
	}

	/*
	 * step 1: load cipher from file
	 */
	private static boolean load_cipher() {
		try {
			File file_path = new File(data_file_path);
			if (!file_path.exists()) {
				System.out.println("[錯誤] text 資料夾不存在，請執行 Encryption 程式進行加密");
				return false;
			}

			Path path = Paths.get(cipher_file);
			String key_file = Files.readString(path);

			key_file = key_file.replaceAll("\n", "");

			cipher_iv = Base64.getDecoder().decode(key_file);

			System.out.println("[狀態] 成功載入密文檔");
		} catch (NoSuchFileException error) {
			// System.out.println("[錯誤]" + error);
			System.out.println("[錯誤] 密文檔 cipher.txt 不存在，請執行 Encryption 程式進行加密");
			return false;
		} catch (Exception error) {
			System.out.println("[錯誤] 程式發生未預期的錯誤" + error);
			return false;
		}
		return true;
	}

	private static boolean finish_genrate_rsa_key() {
		String status = "";
		while (!status.equals("1")) {
			System.out.println("|+++++++++++++++++++++++++++++++++++++++++++++++++++++++|");
			System.out.println("| RSA 金鑰產生完畢                                      \t|");
			System.out.println("| 公鑰檔案已儲存於 key 資料夾中的 rsa_key.pub 檔案         \t|");
			System.out.println("| 私鑰檔案已儲存於 key 資料夾中的 rsa_key.key 檔案         \t|");
			System.out.println("| -> 輸入 1 可返回主頁面                                 \t|");
			System.out.println("|+++++++++++++++++++++++++++++++++++++++++++++++++++++++|");
			status = scanner.next();
			if (status.equals("1")) {
				return true;
			}
		}
		return false;
	}

	private static void genrate_rsa_key() throws NoSuchAlgorithmException, IOException {
		// generate RSA key pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();

		Key pri = kp.getPrivate();
		Key pub = kp.getPublic();

		File file_path = new File(key_file_path);
		if (!file_path.exists()) {
			file_path.mkdir();
		}

		// save RSA private key
		FileWriter out_pri = new FileWriter(rsa_key_file + ".key");
		out_pri.write("-----BEGIN RSA PRIVATE KEY-----\n");
		out_pri.write(Base64.getUrlEncoder().encodeToString(pri.getEncoded()));
		out_pri.write("\n-----END RSA PRIVATE KEY-----\n");
		out_pri.close();

		// save RSA public key
		FileWriter out_pub = new FileWriter(rsa_key_file + ".pub");
		out_pub.write("-----BEGIN RSA PUBLIC KEY-----\n");
		out_pub.write(Base64.getUrlEncoder().encodeToString(pub.getEncoded()));
		out_pub.write("\n-----END RSA PUBLIC KEY-----\n");
		out_pub.close();

		// System.err.println("[資訊] Private key format: " + pri.getFormat());
		// System.err.println("[資訊] Public key format: " + pub.getFormat());

		// System.out.println("[狀態] 成功產生 RSA 2048 金鑰");
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
		System.out.println("| 歡迎使用 Linwebs RSA + AES-CBC 解密系統 \t|");
		System.out.println("| -> 輸入 1 執行解密程式                  \t|");
		System.out.println("| -> 輸入 2 產生 RSA 金鑰                \t|");
		System.out.println("| -> 輸入 3 離開程式                     \t|");
		System.out.println("| 註: 如需加密請執行 Encryption 程式      \t|");
		System.out.println("|+++++++++++++++++++++++++++++++++++++++|");
	}
}
