package cn.zhg.dynamicauth.paillier.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.concurrent.ThreadLocalRandom;

import cn.zhg.dynamicauth.paillier.PaillierKeyPairGenerator;
import cn.zhg.dynamicauth.paillier.PaillierPrivateKey;
import cn.zhg.dynamicauth.paillier.PaillierPublicKey;

/**
 * Paillier工具
 */
public final class PaillierUtil {
	/**调试忽略异常*/
	public static boolean IGNORE=false;
	private PaillierUtil() {
	}
	/**
	 * 生成秘钥对 
	 */
	public static KeyPair generateKeyPair() 
	{
		PaillierKeyPairGenerator gen=new PaillierKeyPairGenerator();
		return gen.generateKeyPair();
	}
	/**
	 * 解密
	 * 
	 * @param privateKey 私钥,不能为null
	 * @param c          密文,不能为null
	 * @return 明文
	 */
	public static BigInteger decrypt(PaillierPrivateKey privateKey, BigInteger c) {
		BigInteger λ = privateKey.getΛ();
		BigInteger u = privateKey.getU();
		BigInteger n = privateKey.getN();
		BigInteger n2 = n.pow(2);
		// c^λ mod n^2
		BigInteger cn = c.modPow(λ, n2);
		// (cn-1)/n
		BigInteger l = cn.subtract(BigInteger.ONE).divide(n);
		// l*u mod n
		BigInteger m = l.multiply(u).mod(n);
		return m;
	}

	/**
	 * 加密
	 * 
	 * @param publicKey 公钥,不能为null
	 * @param m         明文,不能为null
	 * @return 密文和随机数
	 */
	public static BigInteger[] encrypt(PaillierPublicKey publicKey, BigInteger m) {
		return encrypt(publicKey, null, m);
	}

	/**
	 * 加密
	 * 
	 * @param publicKey 公钥,不能为null
	 * @param d         随机数,如果为null,则随机生成
	 * @param m         明文,不能为null
	 * @return 密文和随机数
	 */
	public static BigInteger[] encrypt(PaillierPublicKey publicKey, BigInteger d, BigInteger m) {
		BigInteger g = publicKey.getG();
		BigInteger n = publicKey.getN(); 
		if(!IGNORE&&m.compareTo(n)>=0) {
			throw new IllegalArgumentException("明文m :\n" + m+ "\n必须小于\nn :\n" + n);
		}
		if (d == null) {
			// 需要与n互质
//			d = n.subtract(BigInteger.ONE);
			// 随机一个与n互质的数
			d = gcdBigInteger(n);
			// 快速
//			d = n.add(BigInteger.ONE);
		} else {
			if (!IGNORE&&!d.gcd(n).equals(BigInteger.ONE)) {
				throw new IllegalArgumentException("随机数d :\n" + d + "\n必须互质与\nn :\n" + n); 
			}
		}
		BigInteger n2 = n.pow(2);
		// (g^m)*(d^n) mod n^2
		// a*b mod p=((a mod p)*(b mod p)) mod p
		BigInteger gm = g.modPow(m, n2);
		BigInteger dn = d.modPow(n, n2);
		BigInteger c = gm.multiply(dn).mod(n2);
		return new BigInteger[] { c, d };
	}
	/**
	 * 随机一个与n互质的大数 
	 */
	private static BigInteger gcdBigInteger(BigInteger n) {
		while (true) {
			BigInteger ret = new BigInteger(n.bitLength(), ThreadLocalRandom.current());
			if (ret.gcd(n).equals(BigInteger.ONE)) {
				return ret;
			}
		}
	}
}
