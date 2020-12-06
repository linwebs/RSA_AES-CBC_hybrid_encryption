# 資訊安全與管理 作業 2 1.1
RSA + AES-CBC 混合式加密系統
https://hackmd.io/@linwebs-ncyu/Sk4EKk5ov

> Linwebs 2020.12
> NCYU Information Security and Management

## 目錄
[TOC]

## 題目
Cryptographic Primitives for C++/.NET/Java/Python
The followings are some popular packages for Cryptography:

1. Please apply **two** packages (each encryption mode for one package) to implement the **hybrid encryption**: RSA + AES-CBC and RSA + AES-CTR. You should encrypt plaintext les into ciphertext les, and then decrypt them. Observe and analyze your output results.

Jave RSA + AES-CBC

## 環境
* 程式語言: Java
* 建置平台: Eclipse
* 使用函式庫
	* java.io [檔案讀寫]
	* java.nio.file [檔案讀寫]
	* java.security [AES]
	* java.security.spec [AES]
	* java.util [Base64、標準輸入]
	* javax.crypto [RSA]
* Java 最低版本: Java 8 或更新版
* Java 使用版本: Java JavaSE-14 (jdk-15.0.1)

## 使用說明
1. 請先執行 Decryption.java 產生 RSA 金鑰
2. 執行 Encryption.java 進行加密
3. 執行 Decryption.java 進行解密

※ 請確保擁有執行程式當層資料夾及子資料夾的讀寫權限
※ 請確保讀入的文字檔案編碼為 UTF-8 不帶簽名

## 系統架構)
![encrypt_flow_graph](https://img.linwebs.tw/ewoce)
![decrypt_flow_graph](https://img.linwebs.tw/clekj)

## 程式流程

### 加密流程
| 步驟 | 加密端 | 解密端 |
| ---- | --- | --- |
| 1. |  | 產生 RSA 2048 公鑰、私鑰 |
| 2. |  | 將 RSA 2048 公鑰、私鑰儲存到檔案 |
| 3. | 從檔案讀取 RSA 2048 公鑰 |  |
| 4. | 產生 AES 256 金鑰 |  |
| 5. | 從檔案讀取原文資料 |  |
| 6. | 使用 AES 金鑰加密原文資料成密文 |  |
| 7. | 使用 RSA 公鑰加密 AES 金鑰成被加密的 AES 金鑰 |  |
| 8. | 將密文儲存到檔案 |  |
| 9. | 將被加密的 AES 金鑰儲存到檔案 |  |
| 10. | 完成加密 |  |

### 解密流程
| 步驟 | 加密端 | 解密端 |
| ---- | --- | --- |
| 1. |  | 從檔案讀取密文 |
| 2. |  | 從檔案讀取被加密的 AES 金鑰 |
| 3. |  | 從檔案讀取 RSA 私鑰 |
| 4. |  | 使用 RSA 私鑰解密被加密的 AES 金鑰 |
| 5. |  | 使用解密完成的 AES 解密密文成原文 |
| 6. |  | 儲存解密後的原文資料到檔案 |
| 7. |  | 完成解密 |

## 檔案結構
* Encryption.java [加密]
* Decryption.java [解密、生成 RSA 金鑰]
* text [資料夾]
	* input.txt [原文純文字檔案]
	* aes_key.txt [AES 256 金鑰加密檔]
	* cipher.txt [加密後的密文檔]
	* output.txt [解密後的純文字檔案]
* key [資料夾]
	* rsa_key.key [RSA 2048 私鑰檔]
	* rsa_key.pub [RSA 2048 公鑰檔]

## 執行結果
1. 執行 Decryption.java 產生 RSA 金鑰

![java_gen_rsa_key](https://img.linwebs.tw/uucds)

2. 執行 Encryption.java 進行加密

![java_decrypt](https://img.linwebs.tw/lagnk)

3. 執行 Decryption.java 進行解密

![java_encrypt](https://img.linwebs.tw/oakbg)

## 執行結果分析
以下檔案取自某次的執行結果

* 原文純文字檔案 input.txt
```
abcdefg
hijklmnop
你好嗎?
```

* 解密後的純文字檔案 input.txt
```
abcdefg
hijklmnop
你好嗎?
```

* AES 256 金鑰加密檔 aes_key.txt
```
ituxTdyXS0iaKBjsWJkYsCSeYZqPPJ+XWUUb2E7ab5+CpVoweU5B2Pm4BKpa7RdI4fAK7V7tPfEVkYRQbq5N969kHc26R6/2JHK8DKFKGxpAlhHfsZivjdBFsgOMCCEn4KArMXsU6J0FdNgUqZcJi+3ZQBVc+XTk7Pyk8NnaHbfksA8Be1LP1Rw7U12vW68Rbidz5P9GJ7zeKPUSLrpUcMop25nOTS188V+np1OAK9NsN0HOyB7kP5wlvbE8+K1ef7d9FFbDWN05t8lAW2cUrLB7PDKzKWG0YYo3hlj0qa6NkEX0ZxTRrMdmjN4ugnMfuW17vP9PUR+hX2whUzitIw==
```

* 加密後的密文檔 cipher.txt
```
/kPJdLh6CH7Jbe/zMtX6B54u5X8YjzyjuJm6Aywk6ISPbM6j2BF1szGHSCmPqurI
```

* RSA 2048 私鑰檔 rsa_key.key
```
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMzIJnTxcsL3C-uYEED20yobukwYKP3pgJA0mjca-oBbSGN8tyVdNDTcFsK-rRrGfJU4J9_yg9Vg2hTLhdWcgpOUfd0jksfYnF8FqT1yUQTuliO0T7wVp5T4PJiyh93f1XDYzrBPqMpp87Uaor0fzKTc4cZUfznvPtdTvYctRILpZpuYaFlGi0qGwGGPWu1qnOawoQ850xX0W3n2w2oF2xP8EEqQnwn1BZdR56I27SfDVUn8h201osT7wjL3SfRSgXSY9AenUetZO2pr7iAOr0aTsElGI6SlwECJVuN1HvQUglPEpFLJIfB9MsXtZo-ozneu8fdzZmPhV2Ds4doGtrAgMBAAECggEACxPw5dewYDJ8vcRZBzgyZu-6r7HL9y5KOQqVfCLVJpiQaEYyWg_sapKVKN3DSO4zev9qaphXu-GgwR3eRyZpHlm72nLZpt9viWZz79VOavBpzWd5VsjhtPgpH8jIOu68Gm5gNgJB70PADzxeoRotu1-0C3MrDjGF7k1OHGoxs2nA3WVMew3-_8aA5c8FFlQRWhDqua0xxX-5dQ6xDhRchHUwYdnvzzQkC7EUpS9I9Pz4hRU7QrrRlVAwJ-TeJR9XjmV4mWoA_TyEjq6EY218EbzBHM4K02E6ZQt79jBXIw4IaeferirX5G1u1qMQXUMaU9vQ_l-bUoYsnwyf_62kYQKBgQD4A_3SQgioNWrIFVcMLj_m-rCUFsg92O1_vsTwmntA3o6y8jEBUBQyZr3Ov7XKTaQcH2GJT-uRfPrIvSwVZJlz4sVI_LbMudeOyy1rpVZblAkz6ciaWa0ODEsh9P8EwbFieim6mLhaL7UFDDMOH_aljJfFn680--YPU7TfgE18cQKBgQDTZFlt5snHvCdHDNrVZswUDv85WLQvtMVUGxKDWnjWkkwu2sS_-CSgc5wP8ZrpLNHsbmH3zpTb9OQLupMTZ6AHRUS542MBfT02ccmM3jgQetF8xhPOISuVS7vvIM7F0dZqsQu7EmIEIzjca0fyJWE7_jnUfTXdlm5T5JcYHazDmwKBgQCZSwZIPe5R4WpVrvL1oWR35Hzdm1M6_uiUq5nYSPNjfevfaNinQhKpsF0i-9Vl7CVCCJdlopMsgn4TMvGba2l5ejGMUj6-PSOhq60wOqoswkwJ3TbTSBgxdaG-pEo3a2yzPGSsY5aWj6QoMYkg8tqlKkfoqzFE42koEgnaltfN0QKBgFqp02E7dpdfr0jdzo1wRV7k_7nMvZsoYOmtoscLaoA8xsfhtDjRaIQYkXqVGOeg_Xf177akt1uPMK-HGcVc0FnN76f6SmA9Ip_TNaphNJJ82pQ1MBFcUKD7lmL9IzHcyaWAwZM-UyOLJ7wBlx3XwlhEtPDZstySxEbe557EO3C5AoGAdvt13aQ2xN6vYyVpKp4XVzqAN8kI4JpuWkKbv1_ZjQNYlcCifb19PaVziVho5QxeR1EwKsze2yCdJRrkHfeRCYBWeojQs3cVpKV2XxGB1AXRkpnCymZdDy5GQyURSXRgXYLXBiJhpdh_Zxt_IAn13wgZ_1iX_KicWL7ftkXzr1w=
-----END RSA PRIVATE KEY-----

```

* RSA 2048 公鑰檔 rsa_key.pub
```
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzMyCZ08XLC9wvrmBBA9tMqG7pMGCj96YCQNJo3GvqAW0hjfLclXTQ03BbCvq0axnyVOCff8oPVYNoUy4XVnIKTlH3dI5LH2JxfBak9clEE7pYjtE-8FaeU-DyYsofd39Vw2M6wT6jKafO1GqK9H8yk3OHGVH857z7XU72HLUSC6WabmGhZRotKhsBhj1rtapzmsKEPOdMV9Ft59sNqBdsT_BBKkJ8J9QWXUeeiNu0nw1VJ_IdtNaLE-8Iy90n0UoF0mPQHp1HrWTtqa-4gDq9Gk7BJRiOkpcBAiVbjdR70FIJTxKRSySHwfTLF7WaPqM53rvH3c2Zj4Vdg7OHaBrawIDAQAB
-----END RSA PUBLIC KEY-----

```

由此執行結果可驗證**原文純文字檔案**與**解密後的純文字檔案**內容相符
