package purse;

import javacard.framework.Util;

public class BinaryFile {
	private short size;         //二进投文件的大小
	private byte[] binary;      //二进制文件
	
	public BinaryFile(byte[] pdata){
		size = Util.makeShort(pdata[1], pdata[2]);
		binary = new byte[size];
	}
	
	/*
	 * 功能：写入二进制
	 * 参数：off 写入二进制文件 的偏移量； dl  写入的数据长度； data 写入的数据
	 * 返回：无
	 */
	public final void write_bineary(short off, short dl, byte[] data){
		Util.arrayCopyNonAtomic(data, (short)0, binary, off, dl);
	}
	/*
	 * 功能：读二进制文件
	 * 参数：off 二进制读取的偏移量；len 读取的长度； data 二进制数据的缓冲区
	 * 返回：二进制数据的字节长度
	 */
	public final short read_binary(short off, short len, byte[] data){
		return Util.arrayCopyNonAtomic(binary, off, data, (short)0, len);
	}
	/*
	 * 功能：获取二进制文件大小
	 * 参数：无
	 * 返回：二进制文件的大小
	 */
	public final short get_size(){
		return size;
	}
}
