package purse;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class Randgenerator {
	private byte size;     //随机数的长度
	private byte[] v;      //随机数的值
	private RandomData rd; //随机数的产生机制
	
	public Randgenerator(){
		size = (byte)4;
		v = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		rd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	
	/*
	 * 功能：生成随机数
	 * 参数：无
	 * 返回：无
	 */
	public final void GenerateSecureRnd(){
		rd.generateData(v, (short)0, (short)size);
	}
	
	/*
	 * 功能：获取随机数
	 * 参数：bOff 所获取的数据的偏移量； bf 所存储的数据的值
	 * 返回：随机数的长度
	 */
	public final byte getRndValue(byte[] bf, short bOff){
		Util.arrayCopyNonAtomic(v, (short)0, bf, bOff, (short)size);
		return size;
	}
	
	/*
	 * 功能：获取随机数的长度
	 * 参数：无
	 * 返回：随机数的长度
	 */
	public final byte sizeofRnd(){
		return size;
	}
}
