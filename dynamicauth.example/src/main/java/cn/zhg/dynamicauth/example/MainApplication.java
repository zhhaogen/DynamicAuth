package cn.zhg.dynamicauth.example;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;

import cn.zhg.dynamicauth.paillier.PaillierPublicKey;
import cn.zhg.dynamicauth.paillier.util.PaillierUtil;

public class MainApplication {

	public static void main(String[] args) {
		Scanner reader = new Scanner(System.in); 
		System.out.println("生成秘钥对");
		KeyPair kp = PaillierUtil.generateKeyPair();
		PaillierPublicKey publicKey=(PaillierPublicKey) kp.getPublic();
		System.out.println("生成完成,请保持你的私钥");
		save(kp.getPrivate(), "my.key");
		System.out.println("请输入你的PIN码 :");
		String pin=reader.nextLine();
		//pin加密结果
		BigInteger[] pinRet = PaillierUtil.encrypt(publicKey, new BigInteger(pin)); 
		System.out.println("服务器已保存加密PIN码");
		System.out.println("用户请求授权");
		int captchar = ThreadLocalRandom.current().nextInt(100);
		System.out.println("用户请输入 PIN+"+captchar+"的值 :");
		String user=reader.nextLine();
		//用户计算加密结果
		BigInteger[] userRet = PaillierUtil.encrypt(publicKey,pinRet[1].pow(2), new BigInteger(user));
		//将结果发送给服务器
		System.out.println("服务正在比对结果");
		//随机数加密结果
		BigInteger[] captcharRet = PaillierUtil.encrypt(publicKey,pinRet[1], new BigInteger(String.valueOf(captchar)));
		//pinRet+captcharRet=userRet
		BigInteger e1 = pinRet[0].multiply(captcharRet[0]).mod(publicKey.getN().pow(2));
		BigInteger e2=userRet[0];
		if(e1.equals(e2)) {
			System.out.println("授权成功");
		}else {
			System.out.println("授权失败");
		}
	}

	private static void save(Object obj, String fileName) {
		try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(fileName))) {
			os.writeObject(obj);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
