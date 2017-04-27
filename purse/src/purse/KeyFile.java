package purse;

import javacard.framework.Util;

public class KeyFile {
	public short size;         //记录的最大存储数量
	public short recNum;       //当前所存储的记录数量
	private Object[] Key;      //密钥记录
	
	public KeyFile(){
		size = 4;
		recNum = 0;
		Key = new Object[size];
	}
	
	/*
	 * 功能：添加密
	 * 参数：tag 密钥标识符； length 数值的长度；value 数值（5个字节的密钥头+16个字节的密钥值）
	 * 返回：无
	 */
	public void addkey(byte tag, short length, byte[] value){
		byte[] pbuf;
		
		pbuf = new byte[23];
		Key[recNum] = pbuf;
		pbuf[0] = tag;
		pbuf[1] = (byte)length;
		Util.arrayCopyNonAtomic(value, (short)0, pbuf, (short)2, length);
		
		recNum ++;
	}
	
	/*
	 * 功能：通过密钥标识符获取密钥记录号
	 * 参数：tag 密钥标识符
	 * 返回：记录号
	 */
	public short findkey(byte Tag){
		byte[] pbuf;
		if(recNum == 0)
			return 0;
		
		for(short i = 0;i < recNum;i ++){
			pbuf = (byte[])Key[i];
			if(pbuf[0] == Tag)
				return (short)(i + 1);
		}
		return 0;
	}
	
	/*
	 * 功能：通过密钥类型获取密钥记录号
	 * 参数：type 密钥类型
	 * 返回：记录号
	 */
	public short findKeyByType(byte Type){
		byte[] pbuf;
		if(recNum == 0)
			return 0;
		
		for(short i = 0;i < recNum;i ++){
			pbuf = (byte[])Key[i];
			if(pbuf[2] == Type)
				return (short)(i + 1);
		}
		return 0;
	}
	
	/*
	 * 功能：通过密钥记录号读取密钥
	 * 参数：num 密钥记录号 data 所读取到的密钥缓冲区
	 * 返回：密钥的长度
	 */
	public short readkey(short num, byte[] data){
		byte[] pdata;
		pdata = (byte[])Key[num - 1];
		Util.arrayCopyNonAtomic(pdata, (short)2, data, (short)0, (short)(pdata[1]));
		return (short)(pdata[1] - 5);
	}
	
}
