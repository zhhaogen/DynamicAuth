package cn.zhg.dynamicauth.paillier;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * 公钥
 */
public class PaillierPublicKey implements PublicKey {
 
	private static final long serialVersionUID = 1L;
	private BigInteger n;
	private BigInteger g;
	
	public PaillierPublicKey(BigInteger n, BigInteger g) {
		super();
		this.n = n;
		this.g = g;
	}
	
	public BigInteger getN() {
		return n;
	}

	public BigInteger getG() {
		return g;
	}

	public String getAlgorithm() {
		return "paillier";
	} 
	public String getFormat() {
		return "raw";
	} 
	public byte[] getEncoded() {   
		return null;
	} 
	public String toString() {
		return "{n:" + n + ", g:" + g + "}";
	} 
	
}
