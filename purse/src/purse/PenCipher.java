package purse;

import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class PenCipher {
	private Cipher desEngine;
	private Key deskey;
	
	public PenCipher(){
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	}
	
	/*
	 * 功能：DES运算
	 * 参数：key 密钥; kOff 密钥的偏移量; data 所要进行加解密的数据; dOff 数据偏移量； dLen 数据的长度; r 加解密后的数据缓冲区； rOff 结果数据偏移量； mode 加密或解密运算模式
	 * 返回：无
	 */
	public final void cdes(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode){
		//设置DES密钥
		((DESKey)deskey).setKey(akey, kOff);
		//初始化密钥及加密模式
		desEngine.init(deskey, mode);
		//加密
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	/*
	 * 功能：生成过程密钥
	 * 参数：key 密钥； data 所要加密的数据； dOff 所加密的数据偏移量； dLen 所加密的数据长度； r 加密后的数据； rOff 加密后的数据存储偏移量
	 * 返回：无
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff){
		//todo
		cdes(key, (short) 0, data, dOff, dLen, r, rOff, Cipher.MODE_ENCRYPT);
		cdes(key, (short) 8, r, rOff, dLen, r, rOff, Cipher.MODE_DECRYPT);
		cdes(key, (short) 0, r, rOff, dLen, r, rOff, Cipher.MODE_ENCRYPT);
	}
	
	/*
	 * 功能：8个字节的异或操作
	 * 参数：d1 进行异或操作的数据1 d2:进行异或操作的数据2 d2_off:数据2的偏移量
	 * 返回：无
	 */
	public final void xorblock8(byte[] d1, byte[] d2, short d2_off){
		//todo: 两个数据块进行异或，异或结果存入数据块d1中
		for(short i=0;i<8;i++){
			d1[i] ^= d2[i+d2_off] ;
		}
	}
	
	/*
	 * 功能：字节填充
	 * 参数：data 所要填充的数据； len 数据的长度
	 * 返回：填充后的字节长度
	 */
	public final short pbocpadding(byte[] data, short len){
		//todo: 填充字符串至8的倍数
		data[len]=(byte) 0x80;
		short li = (short) ((len+1)%8);
		if (li != 0) {
			short l= (short) (len+9-li);
			for(short i=(short) (len+1);i<l;i++){
				data[i]=0x00;
			}
			len = l;
		}else {
			len = (short) (len+1);
		}
		return len;
	}
	
	/*
	 * 功能：MAC和TAC的生成
	 * 参数：key 密钥; data 所要加密的数据; dl 所要加密的数据长度； mac 所计算得到的MAC和TAC码
	 * 返回：无
	 */
	public final void gmac4(byte[] key, byte[] data, short dl, byte[] mac){
		//todo
		//先填充，再
		byte[] temp = new byte[8];
		gmac8(key,data,dl,temp);
		
		for (short i = 0; i < 4; i++) {
			mac[i] = temp[i];
		}
	}
	
	public final void gmac8(byte[] key, byte[] data, short dl, byte[] mac){
		//todo
		//先填充，再
		for (short i = 0; i < 8; i++) {
			mac[i] = 0x00;
		}
		
		short len = pbocpadding(data, dl);
		
		for (short i = 0; i < len; i+=8) {
			xorblock8(mac,data,i);
			cdes(key, (short)0, mac, (short)0, (short)8, mac, (short)0, Cipher.MODE_ENCRYPT);
		}
	}
}
