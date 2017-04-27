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
	 * ���ܣ�DES����
	 * ������key ��Կ; kOff ��Կ��ƫ����; data ��Ҫ���мӽ��ܵ�����; dOff ����ƫ������ dLen ���ݵĳ���; r �ӽ��ܺ�����ݻ������� rOff �������ƫ������ mode ���ܻ��������ģʽ
	 * ���أ���
	 */
	public final void cdes(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode){
		//����DES��Կ
		((DESKey)deskey).setKey(akey, kOff);
		//��ʼ����Կ������ģʽ
		desEngine.init(deskey, mode);
		//����
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	/*
	 * ���ܣ����ɹ�����Կ
	 * ������key ��Կ�� data ��Ҫ���ܵ����ݣ� dOff �����ܵ�����ƫ������ dLen �����ܵ����ݳ��ȣ� r ���ܺ�����ݣ� rOff ���ܺ�����ݴ洢ƫ����
	 * ���أ���
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff){
		//todo
		cdes(key, (short) 0, data, dOff, dLen, r, rOff, Cipher.MODE_ENCRYPT);
		cdes(key, (short) 8, r, rOff, dLen, r, rOff, Cipher.MODE_DECRYPT);
		cdes(key, (short) 0, r, rOff, dLen, r, rOff, Cipher.MODE_ENCRYPT);
	}
	
	/*
	 * ���ܣ�8���ֽڵ�������
	 * ������d1 ����������������1 d2:����������������2 d2_off:����2��ƫ����
	 * ���أ���
	 */
	public final void xorblock8(byte[] d1, byte[] d2, short d2_off){
		//todo: �������ݿ�������������������ݿ�d1��
		for(short i=0;i<8;i++){
			d1[i] ^= d2[i+d2_off] ;
		}
	}
	
	/*
	 * ���ܣ��ֽ����
	 * ������data ��Ҫ�������ݣ� len ���ݵĳ���
	 * ���أ�������ֽڳ���
	 */
	public final short pbocpadding(byte[] data, short len){
		//todo: ����ַ�����8�ı���
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
	 * ���ܣ�MAC��TAC������
	 * ������key ��Կ; data ��Ҫ���ܵ�����; dl ��Ҫ���ܵ����ݳ��ȣ� mac ������õ���MAC��TAC��
	 * ���أ���
	 */
	public final void gmac4(byte[] key, byte[] data, short dl, byte[] mac){
		//todo
		//����䣬��
		byte[] temp = new byte[8];
		gmac8(key,data,dl,temp);
		
		for (short i = 0; i < 4; i++) {
			mac[i] = temp[i];
		}
	}
	
	public final void gmac8(byte[] key, byte[] data, short dl, byte[] mac){
		//todo
		//����䣬��
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
