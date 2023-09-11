package cn.zhg.dynamicauth.paillier;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 秘钥对生成
 */
public class PaillierKeyPairGenerator  extends KeyPairGenerator {
	private Random random;
	private int keysize;
	/** 最大尝试次数 */
	private int maxTry;

	public PaillierKeyPairGenerator() {
		super("paillier");
		keysize = 1024;
		maxTry = 20;
	}

	public void initialize(int keysize, SecureRandom random) {
		this.random = random;
		this.keysize = keysize;
	}

	public void initialize(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {
		this.random = random;
	}
	public KeyPair generateKeyPair() {
		if (random == null) {
			random = ThreadLocalRandom.current();
		}
		for (int i = 0; i < maxTry; i++) {
			// 循环直到合适的结果
			//todo 注意这可能是质数
			BigInteger p = BigInteger.probablePrime(keysize, random);
			BigInteger q = BigInteger.probablePrime(keysize, random);
			// p*q
			BigInteger n = p.multiply(q);
			// n^2
			BigInteger n2 = n.pow(2);
			// (p-1)*(q-1)
			BigInteger n1 = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
			// gcd(pq,(p-1)*(q-1))
			BigInteger gcd12 = n2.gcd(n1);
			if (!gcd12.equals(BigInteger.ONE)) {
				// p、q不符合
				continue;
			}
			KeyPair keyPair = generate(p, q, n, n1, n2, random);
			if (keyPair != null) {
				return keyPair;
			}
		}
		return null;
	}
	/**
	 * @param p   选取的质数
	 * @param q   选取的质数
	 * @param n   p*q
	 * @param n1  (p-1)*(q-1)
	 * @param n2  n^2
	 * @param rnd
	 * @return 成功符合则返回,失败则返回null
	 */
	private KeyPair generate(BigInteger p, BigInteger q, BigInteger n, BigInteger n1, BigInteger n2, Random rnd) {

		for (int i = 0; i < maxTry; i++) {
			// 随机选取一个g<n2
			BigInteger g = n.add(BigInteger.ONE);
//			BigInteger g = nextBigInteger(n2, rnd);
			// lcm(p-1,q-1)
			BigInteger λ = n1.divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
			// g^r mod n^2
			BigInteger x = g.modPow(λ, n2);
			// (x-1)/n
			BigInteger l = x.subtract(BigInteger.ONE).divide(n);
			// u=l^-1 mod n ,或 ul=1 mod n ,为模逆元 ,指ul mod n =1 ,ul取模n,结果为1
			// 求模逆元
			try {
				BigInteger u = l.modInverse(n);
				PaillierPublicKey publicKey = new PaillierPublicKey(n, g);
				PaillierPrivateKey privateKey = new PaillierPrivateKey(λ, u, n);
				return new KeyPair(publicKey, privateKey);
			} catch (ArithmeticException ex) {
			}
		}
		return null;
	}
}
