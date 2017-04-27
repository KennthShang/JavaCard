package purse;

import javacard.framework.JCSystem;

public class Papdu {
	public byte cla, ins, p1, p2;
	public short lc, le;
	public byte[] pdata;
	
	public Papdu(){
		//apdu的数据段部分最大长度为255字节
		pdata = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);
	}
	
	/*
	 * 功能：判断APDU命令是包含数据
	 * 参数：无
	 * 返回：APDU命令包含数据的判断
	 */
	public boolean APDUContainData(){
		switch(ins){
		case condef.INS_CREATE_FILE:
		case condef.INS_LOAD:
		case condef.INS_INIT_TRANS:
		case condef.INS_WRITE_KEY:
		case condef.INS_WRITE_BIN:
		case condef.INS_PURCHASE:
			
			return true;
		}
		return false;
	}
}
