package cn.zhg.dynamicauth.common.util;

import javax.script.Bindings;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.SimpleBindings;

/**
 * 表达式工具
 */
public final class ExpressionUtil {
	private static ThreadLocal<ScriptEngine> jsEng=ThreadLocal.withInitial(()->{
		ScriptEngineManager sm=new ScriptEngineManager(); 
		ScriptEngine jsEng = sm.getEngineByMimeType("application/javascript");
		return jsEng;
	});
	private ExpressionUtil() {}
	/**
	 * 简单计算表达式
	 * @param f 表达式,不能为空
	 * @param a 变量值
	 * @return
	 */
	public static int calc(String f,int a) {
		int a1=a%10;
		int a2=(a/10)%10;
		int a3=(a/100)%10;
		int a4=(a/1000)%10;

		Bindings binding=new SimpleBindings();
		binding.put("a", a);
		binding.put("a1", a1);
		binding.put("a2", a2);
		binding.put("a3", a3);
		binding.put("a4", a4);
		try { 
			Object ret = jsEng.get().eval(f, binding);
			if(ret instanceof Integer) {
				return (int) ret;
			}
			if(ret instanceof Number) {
				return ((Number) ret).intValue();
			}
			return Integer.parseInt(ret.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return a; 
	}
}
