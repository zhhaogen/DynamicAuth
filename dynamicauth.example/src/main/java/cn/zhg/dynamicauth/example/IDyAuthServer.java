package cn.zhg.dynamicauth.example;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * 动态授权服务
 */
public interface IDyAuthServer  extends Remote{
	/**
	 * 生成秘钥对 
	 */
	KeyPair createKeyPair(int userId) throws RemoteException;
	/**
	 * 设置PIN码
	 */
	void setPin(int userId,int pin) throws RemoteException;
	/**
	 * 设置code运算函数
	 */
	void setCodeFun(int userId,String f) throws RemoteException;
	/**
	 * 请求授权
	 * @return 随机数和加密随机数
	 */
	BigInteger[] requestAuth(int userId) throws RemoteException;
	/**
	 * 进行授权
	 */
	boolean auth(int userId,BigInteger b) throws RemoteException;
	/**
	 * 获取公钥 
	 */
	PublicKey getPublicKey(int userId)throws RemoteException; 
}
