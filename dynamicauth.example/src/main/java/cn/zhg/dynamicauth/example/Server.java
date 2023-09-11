package cn.zhg.dynamicauth.example;

import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;

/**
 * 启动服务端
 */
public class Server {

	public static void main(String[] args) {
		try {
			DyAuthServer service = new DyAuthServer();
			UnicastRemoteObject.exportObject(service, 0);
			LocateRegistry.createRegistry(8090).bind("dyAuthServer", service);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
