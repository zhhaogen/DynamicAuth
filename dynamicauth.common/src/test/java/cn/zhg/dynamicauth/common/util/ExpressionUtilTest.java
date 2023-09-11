package cn.zhg.dynamicauth.common.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.Test;

public class ExpressionUtilTest {

	@Test
	public void test() {
		int a = ThreadLocalRandom.current().nextInt(1000,10000);
		test("a", a);
		test("a1", a);
		test("a2", a);
		test("a3", a);
		test("a4", a);
		test("a+2", a);
		test("a2+a1", a);
		test("2*a2", a);
		test("2*a2+a1+a3", a);
		test("a1+10*a2+100*a3+1000*a4", a);
	}

	void test(String f, int a) {
		int ret = ExpressionUtil.calc(f, a);
		System.out.println("a="+a+","+f+"="+ret);
	}
}
