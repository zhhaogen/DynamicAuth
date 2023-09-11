package cn.zhg.dynamicauth.example;

import java.math.BigInteger;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyPair;
import java.util.Scanner;

import cn.zhg.dynamicauth.paillier.PaillierPublicKey;
import cn.zhg.dynamicauth.paillier.util.PaillierUtil;

/**
 * 启动客户端
 */
public class Client {

	public static void main(String[] args) {
		// 模拟用户ID
		int userId = 2; 
		IDyAuthServer api;
		try {
			Registry registry = LocateRegistry.getRegistry("127.0.0.1", 8090);
			api = (IDyAuthServer) registry.lookup("dyAuthServer");
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
		Scanner reader = new Scanner(System.in);
//		KeyPair kp = null;
		PaillierPublicKey publicKey = null;
		while (true) {
			System.out.println("请选择");
			System.out.println("1 .生成秘钥对");
			System.out.println("2 .设置PIN");
			System.out.println("3 .设置运算函数");
			System.out.println("4 .请求授权");
			System.out.println("5 .获取公钥");
			System.out.println("输入bye结束程序");
			String line = reader.nextLine();
			if (line.equalsIgnoreCase("bye")) {
				reader.close();
				return;
			}
			if ("1".equals(line)) {
				KeyPair kp = tryCatch(() -> api.createKeyPair(userId));
				publicKey=(PaillierPublicKey) kp.getPublic();
				System.out.println("成功");
				continue;
			}
			if ("2".equals(line)) {
				System.out.println("请输入PIN :");
				String s = reader.nextLine();
				tryCatch(() -> api.setPin(userId, Integer.parseInt(s)));
				System.out.println("成功");
				continue;
			}
			if ("3".equals(line)) {
				System.out.println("a代表code,a1代表个位数,a2代表百位数,以此类推");
				System.out.println("请输入表达式f :"); 
				String s = reader.nextLine();
				tryCatch(() -> api.setCodeFun(userId, s));
				System.out.println("成功");
				continue;
			}
			if ("4".equals(line)) {
				BigInteger[] datas = tryCatch(() -> api.requestAuth(userId));
				System.out.println("请输入PIN+f(" + datas[0] + ")=? :");
				line = reader.nextLine(); 
				BigInteger[] ret = PaillierUtil.encrypt(publicKey, datas[1].pow(2), new BigInteger(line));
				boolean b = tryCatch(() -> api.auth(userId, ret[0]));
				if (b) {
					System.out.println("授权成功");
				} else {
					System.out.println("授权失败");
				}
				continue;
			}
			if ("5".equals(line)) {
				publicKey= (PaillierPublicKey) tryCatch(() -> api.getPublicKey(userId));
				continue;
			}
		} 
	}
 
	private static <T> T tryCatch(ESupplier<T> run) {
		try {
			return run.get();
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return null;
	}

	private static void tryCatch(ERunnable run) {
		try {
			run.run();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	private static interface ERunnable {
		void run() throws Throwable;
	}

	private static interface ESupplier<T> {
		T get() throws Throwable;
	}
}
