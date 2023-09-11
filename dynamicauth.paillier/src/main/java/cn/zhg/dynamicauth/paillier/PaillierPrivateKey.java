package cn.zhg.dynamicauth.paillier;

import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * 私钥
 */
public class PaillierPrivateKey implements PrivateKey { 
	private static final long serialVersionUID = 1L;
	private BigInteger λ;
	private BigInteger u;
	private BigInteger n;
	
	public PaillierPrivateKey(BigInteger λ, BigInteger u, BigInteger n) {
		super();
		this.λ = λ;
		this.u = u;
		this.n = n;
	}
	public BigInteger getΛ() {
		return λ;
	}
	public BigInteger getU() {
		return u;
	}
	public BigInteger getN() {
		return n;
	} 
	public String toString() {
		return "{λ:" + λ + ", u:" + u + ", n:" + n + "}";
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
}
