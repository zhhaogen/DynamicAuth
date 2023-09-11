package cn.zhg.dynamicauth.example;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import cn.zhg.dynamicauth.common.util.ExpressionUtil;
import cn.zhg.dynamicauth.paillier.PaillierPublicKey;
import cn.zhg.dynamicauth.paillier.util.PaillierUtil;

public class DyAuthServer implements IDyAuthServer {
	/**
	 * 数据库中的用户表
	 */
	private static Map<Integer,UserInfo> usersTable=new HashMap<>();
	/**
	 * session
	 */
	private static Map<String,Object> session=new HashMap<>();
	public DyAuthServer() {}

	public KeyPair createKeyPair(int userId) {
		UserInfo userInfo = usersTable.getOrDefault(userId, new UserInfo());
		KeyPair kp = PaillierUtil.generateKeyPair();
		PaillierPublicKey publicKey = (PaillierPublicKey) kp.getPublic();
		//储存用户公钥
		userInfo.publicKey=publicKey;
		usersTable.put(userId, userInfo);
		return kp;
	} 
	public void setPin(int userId, int pin) {
		UserInfo userInfo =usersTable.get(userId);
		//对PIN进行加密储存
		BigInteger[] ret = PaillierUtil.encrypt(userInfo.publicKey, new BigInteger(String.valueOf(pin)));
		userInfo.ePin=ret[0];
		userInfo.d=ret[1];
		usersTable.put(userId, userInfo);
	} 
	public void setCodeFun(int userId, String f) throws RemoteException {
		UserInfo userInfo =usersTable.get(userId);
		userInfo.f=f;
		usersTable.put(userId, userInfo);
	}
	public BigInteger[] requestAuth(int userId) {
		//生成4位随机数
		int c = ThreadLocalRandom.current().nextInt(1000,10000);
		UserInfo userInfo =usersTable.get(userId);
		session.put(userId+"_auth_code", c);
		return new BigInteger[] {new BigInteger(String.valueOf(c)),userInfo.d};
	}  
	public boolean auth(int userId, BigInteger b) {
		UserInfo userInfo =usersTable.get(userId);
		int c = (int) session.get(userId+"_auth_code"); 
		c=ExpressionUtil.calc(userInfo.f, c);
		//对随机数加密
		BigInteger ec = PaillierUtil.encrypt(userInfo.publicKey,userInfo.d,new BigInteger(String.valueOf(c)))[0];
		//ePin+ec
		BigInteger ret=userInfo.ePin.multiply(ec).mod(userInfo.publicKey.getN().pow(2));
		//进行验证 
		return ret.equals(b);
	}  
	public PublicKey getPublicKey(int userId) throws RemoteException {
		UserInfo userInfo =usersTable.get(userId);
		return userInfo.publicKey;
	}
	/**
	 * 用户信息
	 */
	private static class UserInfo{

		public BigInteger d;
		public BigInteger ePin;
		public PaillierPublicKey publicKey;
		public String f;
	} 
	
}
