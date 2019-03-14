package com.htschk.crm.data_service.utils;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
 
import javax.crypto.Cipher;
 
import org.apache.commons.codec.binary.Base64;

/**
 * 支持117 Byte字符解码 AT MAX
 * @author wangxiao
 *
 */
public class RSAUtil {
    
    private static void initKey(){
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(1024, random);
            KeyPair keyPair = generator.generateKeyPair();
            saveKeyPair(keyPair);
        }catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    private static void saveKeyPair(KeyPair kp) throws Exception{
        FileOutputStream fos = new FileOutputStream(RSAUtil.class.getResource("/RSAKey").getPath());
        //FileOutputStream fos = new FileOutputStream("C:/temp/RSAKey.txt"); 
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        //生成密钥  
        oos.writeObject(kp);
        oos.close();
        fos.close();
    }
    
    private static KeyPair getKeyPair() throws Exception{
        //FileInputStream fis = new FileInputStream("C:/temp/RSAKey.txt");
        InputStream fis = RSAUtil.class.getResourceAsStream("/RSAKey");
		ObjectInputStream oos = new ObjectInputStream(fis);
		KeyPair kp= (KeyPair) oos.readObject();
		oos.close();
		fis.close();
		return kp;
    }
 
    /**
     * 生成public key
     * @return
     * @throws Exception 
     */
    public static String generateBase64PublicKey() throws Exception{
        RSAPublicKey key = (RSAPublicKey)getKeyPair().getPublic();
        return new String(Base64.encodeBase64(key.getEncoded()));
    }
    
    /**
     * 生成priavete key
     * @return
     * @throws Exception 
     */
    public static String generateBase64PrivateKey() throws Exception{
        RSAPrivateKey key = (RSAPrivateKey)getKeyPair().getPrivate();
        return new String(Base64.encodeBase64(key.getEncoded()));
    }
     
    /**
     * 解密
     * @param string
     * @return
     */
    public static String decryptBase64(String string) {
        return new String(decrypt(Base64.decodeBase64(string)));
    }
     
    private static byte[] decrypt(byte[] string) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
            RSAPrivateKey pbk = (RSAPrivateKey)getKeyPair().getPrivate();
            cipher.init(Cipher.DECRYPT_MODE, pbk);
            byte[] plainText = cipher.doFinal(string);
            return plainText;
        }catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
     
    public static void main(String[] args) {
    	//initKey();
    	try {
        // 生成public key
			//System.out.println(generateBase64PublicKey());
			System.out.println("**********************");
		    // 解密
		    System.out.println(decryptBase64("arQeSiVbxX6Jw943miTqyBsYFIw8/qYKUtxlTJIDycxGkK2HLa2+eCsskJ48nurbI3AuMEXYhMAmd85ZkvDzr8tkh8BVWSmEjP5dAz8RsTL/iV3BGZKhzWiAPkTgztKbMVgHH9DSe+7vK6xe94WJ+XuHpDporLPJGoAUUvYqa7w="));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
