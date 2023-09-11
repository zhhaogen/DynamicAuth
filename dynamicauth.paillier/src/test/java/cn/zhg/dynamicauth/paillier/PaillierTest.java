package cn.zhg.dynamicauth.paillier;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.Test;

import cn.zhg.dynamicauth.paillier.util.PaillierUtil;

public class PaillierTest {
	/**
	 * 可能概率限制
	 */
	private static final int probable = 100;
	@Test
	public void testGenerateKeyPair() {
		PaillierKeyPairGenerator generator = new PaillierKeyPairGenerator();
		KeyPair kp = generator.generateKeyPair();
		System.out.println(kp);
	}
	@Test
	public void testCheck() {
		KeyPair kp = check(new BigInteger("7"), new BigInteger("11"), new BigInteger("5652"));
		System.out.println("公钥 :");
		System.out.println(kp.getPublic());
		System.out.println("私钥 :");
		System.out.println(kp.getPrivate());
	}

	@Test
	public void testCheck2() {
		KeyPair kp = check(new BigInteger("7"), new BigInteger("11"), new BigInteger("5652"));
		// 明文
		BigInteger m = new BigInteger("23");
		testVerifier(kp, m);
	}

	@Test
	public void testCheck3() {
		PaillierUtil.IGNORE=true;
		KeyPair kp = check(new BigInteger("11"), new BigInteger("19"), new BigInteger("147"));
		// 明文
		BigInteger m = new BigInteger("8");
		//指定随机数
		testVerifier(kp, m, new BigInteger("3"));
		//随机数使用互质
//		testVerifier(kp, m, new BigInteger("11"));
//		testVerifier(kp, m, new BigInteger("19"));
		//
//		testVerifier(kp, new BigInteger("11"), new BigInteger("3"));
//		testVerifier(kp, new BigInteger(""+(11*19-1)) );
//		testVerifier(kp, new BigInteger(""+(11*19)) );
//		testVerifier(kp, new BigInteger(""+(11*19+1)) );
	}
	/**
	 * 检验选取数是否符合条件
	 * 
	 * @param p 选取的质数
	 * @param q 选取的质数
	 * @param g 选取的整数
	 */
	KeyPair check(BigInteger p, BigInteger q, BigInteger g) {
		if (!p.isProbablePrime(probable)) {
			System.out.println("p :\n" + p + "\n不是质数");
			return null;
		}
		if (!q.isProbablePrime(probable)) {
			System.out.println("q :\n" + q + "\n不是质数");
			return null;
		}
		// p*q
		BigInteger n = p.multiply(q);
		// n^2
		BigInteger n2 = n.pow(2); 
		// (p-1)*(q-1)
		BigInteger n1 = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		// gcd(pq,(p-1)*(q-1))
		BigInteger gcd12 = n2.gcd(n1);
		if (!gcd12.equals(BigInteger.ONE)) {
			System.out.println("pq :\n" + n1 + "\n(p-1)*(q-1) :\n" + n2 + "\n应该互质,最大公约数结果 :" + gcd12);
			return null;
		}
		// lcm(p-1,q-1)
		BigInteger r = n1.divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
		// g^r mod n^2
		BigInteger x = g.modPow(r, n2);
		// (x-1)/n
		BigInteger l = x.subtract(BigInteger.ONE).divide(n);
		// u=l^-1 mod n ,或 ul=1 mod n ,为模逆元 ,指ul mod n =1 ,ul取模n,结果为1
		// 求模逆元
		try {
			BigInteger u = l.modInverse(n);
//			System.out.println("公钥 :\n" + n + "\n" + g);
//			System.out.println("私钥 :\n" + r + "\n" + u);
			PaillierPublicKey publicKey = new PaillierPublicKey(n, g);
			PaillierPrivateKey privateKey = new PaillierPrivateKey(r, u, n);
			return new KeyPair(publicKey, privateKey);
		} catch (ArithmeticException ex) {
			System.out.println("l :\n" + l + "\nn :\n" + n + "\n l^-1 mod n没有模逆元");
			return null;
		}
	}
	/**
	 * 验证加密解密
	 */
	@Test
	public void testVerifier() {
		PaillierKeyPairGenerator generator = new PaillierKeyPairGenerator();
		KeyPair kp = generator.generateKeyPair();
		// 明文
//		BigInteger m = new BigInteger("23");
		for (int i = 0; i < 10; i++) {
			BigInteger m = new BigInteger(String.valueOf(ThreadLocalRandom.current().nextInt(3000)));
			testVerifier(kp, m);
		}

	}

	/**
	 * 验证加密解密
	 */
	void testVerifier(KeyPair kp, BigInteger m) {
		testVerifier(kp, m, null);
	}

	/**
	 * 验证加密解密
	 */
	void testVerifier(KeyPair kp, BigInteger m, BigInteger d) {
		PaillierPublicKey publicKey = (PaillierPublicKey) kp.getPublic();

		System.out.println("m明文 :\n" + m);
		BigInteger[] ret = PaillierUtil.encrypt(publicKey, d, m);
		System.out.println("加密随机数 :\n" + ret[1]);
		BigInteger c = ret[0];
		System.out.println("Enc(m)密文 :\n" + c);

		// 解密
		PaillierPrivateKey privateKey = (PaillierPrivateKey) kp.getPrivate();
		BigInteger m2 = PaillierUtil.decrypt(privateKey, c);
		System.out.println("Dec(c)解密 :\n" + m2);
		assertEquals(m, m2);
	} 
	/**
	 * 验证加法同态性
	 */
	@Test
	public void testAdd() {
		PaillierKeyPairGenerator generator = new PaillierKeyPairGenerator();
		KeyPair kp = generator.generateKeyPair();
		// 明文
		testAdd(kp, new BigInteger("23"), new BigInteger("49"));
	}

	/**
	 * 验证加法同态性,使用相同随机数
	 */
	@Test
	public void testAdd2() {
		PaillierKeyPairGenerator generator = new PaillierKeyPairGenerator();
		KeyPair kp = generator.generateKeyPair(); 
		// 明文
		testAdd2(kp, new BigInteger("23"), new BigInteger("49"));
	}

	/**
	 * 验证加法同态性,使用相同随机数
	 */
	void testAdd2(KeyPair kp, BigInteger a, BigInteger b) {
		BigInteger ab = a.add(b);
		System.out.println("a+b=" + a + "+" + b + "=" + ab);
		PaillierPublicKey publicKey = (PaillierPublicKey) kp.getPublic(); 
		// a加密
		BigInteger[] ret = PaillierUtil.encrypt(publicKey, a);
		BigInteger ea = ret[0];
		// 记录随机数
		BigInteger d1 = ret[1];
		System.out.println("加密随机数 :\n" + d1);
		System.out.println("加密(a) ea :\n" + ea);
		assertEquals(PaillierUtil.decrypt((PaillierPrivateKey) kp.getPrivate(), ea), a);
		// b加密
		ret = PaillierUtil.encrypt(publicKey, b);
		BigInteger eb = ret[0];
		// 记录随机数
		BigInteger d2 = ret[1];
		System.out.println("加密随机数 :\n" + d2);
		System.out.println("加密(b) eb :\n" + eb);
		assertEquals(PaillierUtil.decrypt((PaillierPrivateKey) kp.getPrivate(), eb), b);
		// 密文相乘
		BigInteger eaeb = ea.multiply(eb).mod(publicKey.getN().pow(2));
		System.out.println("ea*eb mod n^2= :\n" + eaeb);
		assertEquals(PaillierUtil.decrypt((PaillierPrivateKey) kp.getPrivate(), eaeb), ab);

		BigInteger d3 = d1.multiply(d2);
		ret =  PaillierUtil.encrypt(publicKey,d3, ab);
		BigInteger eab = ret[0]; 
		System.out.println("加密随机数 :\n" + d3);
		System.out.println("加密(a+b) :\n" + eab);
		if (eab.equals(eaeb)) {
			System.out.println("Enc(a)*Enc(b) mod n^2=Enc(a+b)");
		} else {
			System.err.println("Enc(a)*Enc(b)  mod n^2 !=Enc(a+b)");
		}
	}

	/**
	 * 验证加法同态性
	 */
	void testAdd(KeyPair kp, BigInteger a, BigInteger b) {
		BigInteger ab = a.add(b);
		System.out.println("a+b=" + a + "+" + b + "=" + ab);
		PaillierPublicKey publicKey = (PaillierPublicKey) kp.getPublic();
		// a加密
		BigInteger[] ret = PaillierUtil.encrypt(publicKey, a);
		BigInteger ea = ret[0];
		BigInteger d1=ret[1];
		System.out.println("加密(a) ea :\n" + ea);
		assertEquals(PaillierUtil.decrypt((PaillierPrivateKey) kp.getPrivate(), ea), a);
		// b加密
		ret =  PaillierUtil.encrypt(publicKey, b);
		BigInteger eb = ret[0];
		BigInteger d2=ret[1];
		System.out.println("加密(b) eb :\n" + eb);
		assertEquals(PaillierUtil.decrypt((PaillierPrivateKey) kp.getPrivate(), eb), b);
		// 密文相乘 为加法算符
		BigInteger eaeb = ea.multiply(eb);
		//mod n^2对于解密来说无影响
//		eaeb=eaeb.mod(publicKey.getN().pow(2));
		System.out.println("ea*eb mod n^2 = :\n" + eaeb);
		PaillierPrivateKey privateKey = (PaillierPrivateKey) kp.getPrivate();
		BigInteger dab =  PaillierUtil.decrypt(privateKey, eaeb);
		System.out.println("解密(ea*eb) :\n" + dab);
		if (dab.equals(ab)) {
			System.out.println("Dec(Enc(a)*Enc(b))=a+b");
		} else {
			System.err.println("Dec(Enc(a)*Enc(b))!=a+b");
		}
		//这里要使用前面两个加密随机数
		ret = PaillierUtil.encrypt(publicKey, d1.multiply(d2),ab);
		BigInteger eab = ret[0];
		System.out.println("加密(a+b) :\n" + eab);
		//这里先要对ea*eb 进行取模运算
		eaeb=eaeb.mod(publicKey.getN().pow(2));
		if (eab.equals(eaeb)) {
			System.out.println("Enc(a)*Enc(b)=Enc(a+b)");
		} else {
			System.err.println("Enc(a)*Enc(b)!=Enc(a+b)");
		}
	}
}
