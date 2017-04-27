package purse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class Purse extends Applet {
	//APDU Object
	private Papdu papdu;
	
	//�ļ�ϵͳ
	private KeyFile keyfile;            //��Կ�ļ�
	private BinaryFile cardfile;        //Ӧ�û����ļ�
	private BinaryFile personfile;      //�ֿ��˻����ļ�
	private EPFile EPfile;              //����Ǯ���ļ�
	
	private PenCipher TestCipher;  // for test
	
	public Purse(byte[] bArray, short bOffset, byte bLength){
		papdu = new Papdu();
		TestCipher = new PenCipher();
		byte aidLen = bArray[bOffset];
		if(aidLen == (byte)0x00)
			register();
		else
			register(bArray, (short)(bOffset + 1), aidLen);
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Purse(bArray, bOffset, bLength);
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}		
		//����1:ȡAPDU�������������ò���֮�����½�����
		byte[] buffer = apdu.getBuffer();
		//����2��ȡAPDU�����������ݷŵ�����papdu
		//short lc = apdu.setIncomingAndReceive();
		apdu.setIncomingAndReceive();
		
		papdu.cla = buffer[ISO7816.OFFSET_CLA];
		papdu.ins = buffer[ISO7816.OFFSET_INS];
		papdu.p1 = buffer[ISO7816.OFFSET_P1];
		papdu.p2 = buffer[ISO7816.OFFSET_P2];
		//papdu.lc = buf[ISO7816.OFFSET_LC];
		
		//����3���ж�����APDU�Ƿ�������ݶΣ����������ȡ���ݳ��ȣ�����le��ֵ�����򣬼�����Ҫlc��data�����ȡ������ԭ��lcʵ������le
		//if (papdu.APDUContainData()) {} || if (lc > 0)
		if (papdu.APDUContainData()){
			papdu.lc = buffer[ISO7816.OFFSET_LC];
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, papdu.pdata, (short) 0, papdu.lc);
			if (buffer.length-ISO7816.OFFSET_CDATA == papdu.lc) {
				papdu.le = 0;
			} else {
				papdu.le = buffer[buffer.length-1];
			}
		} else {
			papdu.le = buffer[ISO7816.OFFSET_LC];
			papdu.lc=0;
		}
		
		boolean rc = handleEvent();
		//����4:�ж��Ƿ���Ҫ�������ݣ�������apdu������	
		//ע�⣺����0xB0δ���壬֮���ٶ���
		if (rc&&papdu.le>0) {
			Util.arrayCopyNonAtomic(papdu.pdata, (short) 0, buffer, (short) 0, papdu.le);
			apdu.setOutgoingAndSend((short) 0, papdu.le);
		}
		
		//����Ϊ���Բ���
		/*if (rc&&papdu.ins==(byte)0xcc) {
			Util.arrayCopyNonAtomic(papdu.pdata, (short) 0, buffer, (short) 0, papdu.le);
			apdu.setOutgoingAndSend((short) 0, papdu.le);
		}*/
	}

	/*
	 * ���ܣ�������ķ����ʹ���
	 * ��������
	 * ���أ��Ƿ�ɹ�����������
	 */
	private boolean handleEvent(){
		switch(papdu.ins){
		    case (byte) 0xcc:              return Test();
		    case condef.INS_GET_SESPK:     return get_sespk();
		    case condef.INS_GET_MAC:       return get_mac();
		   //todo�����д��������������������д��Կ����
			case condef.INS_CREATE_FILE:     return create_file();
			case condef.INS_WRITE_BIN:       return write_bin();
			case condef.INS_WRITE_KEY:       return write_key();
			case condef.INS_READ_BIN:        return read_bin();
			case condef.INS_GET_BALANCE:     return get_balance();
			case condef.INS_PURCHASE:        return purchase();
			case condef.INS_LOAD:            return load();
			case condef.INS_INIT_TRANS:            
				if(papdu.p1==(byte)0x00)     return init_load();
				if(papdu.p1==(byte)0x01)     return init_purchase();
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}	
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		return false;
	}

	private boolean read_bin() {
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		if (papdu.p1 == 0x16) {
			cardfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		} else if (papdu.p1 == 0x17) {
			personfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		}
		return true;
	}

	private boolean write_key() {
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (byte)0x15)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(keyfile == null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		keyfile.addkey(papdu.p2, papdu.lc, papdu.pdata);
		return true;
	}

	private boolean write_bin() {
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if (papdu.p1 == 0x16) {
			cardfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		} else if (papdu.p1 == 0x17) {
			personfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		}
		
		return true;
	}

	/*
	 * ���ܣ������ļ�
	 */
	private boolean create_file() {
		switch(papdu.pdata[0]){             
		case condef.EP_FILE:        return EP_file();  
		//todo:��ɴ�����Կ�ļ����ֿ��˻����ļ���Ӧ�û����ļ�
		case condef.KEY_FILE:        return KEY_file();  
		case condef.CARD_FILE:        return CARD_file();  
		case condef.PERSON_FILE:        return PERSON_file();  
		default: 
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		return true;
	}
	
	private boolean PERSON_file() {
		//throws some exceptions
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		if(papdu.p1 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		
		personfile = new BinaryFile(papdu.pdata);
		return true;
	}

	private boolean CARD_file() {
		//throws some exceptions
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		if(papdu.p1 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		cardfile = new BinaryFile(papdu.pdata);
		return true;
	}

	private boolean KEY_file() {
		//throws some exceptions
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		if(papdu.p1 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		keyfile = new KeyFile();
		return true;
	}

	/*
	 * ���ܣ���������Ǯ���ļ�
	 */
	private boolean EP_file() {
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		EPfile = new EPFile(keyfile);
		
		return true;
	}	
	
	/*
	 * ���ܣ�Ȧ�������ʵ��
	 */
	private boolean load() {
		short rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		rc = EPfile.load(papdu.pdata);
		
		if(rc == 1)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_LOAD_FULL);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)4;
		
		return true;
	}

	/*
	 * ���ܣ�Ȧ���ʼ�������ʵ��
	 */
	private boolean init_load() {
		short num,rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		num = keyfile.findkey(papdu.pdata[0]);
		
		if(num == 0x00)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4load(num, papdu.pdata);
		
		if(rc == 2)
			ISOException.throwIt((condef.SW_LOAD_FULL));
		
		papdu.le = (short)0x10;
		
		return true;
	}
	
	/*
	 * ���ܣ����������ʵ��
	 */
	private boolean purchase(){
		short rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		if(papdu.lc != (short)0x0F)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		rc = EPfile.purchase(papdu.pdata);
		
		if(rc == 1)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)8;
		return true;
	}
	
	/*
	 * ���ܣ����ѳ�ʼ����ʵ��
	 */
	private boolean init_purchase(){
		short num,rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		num = keyfile.findkey(papdu.pdata[0]);
		
		if(num == 0x00)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4purchase(num, papdu.pdata);
		
		if(rc == 2)
			ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
		
		papdu.le = (short)0x0F;
		
		return true;
	}
	
	/*
	 * ���ܣ�����ѯ���ܵ�ʵ��
	 */
	private boolean get_balance(){
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		papdu.le = (short)4;
		
		EPfile.get_balance(papdu.pdata);
		return true;
	}

	private boolean get_mac() {
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		papdu.le = (short)4;
		
		byte[] data = new byte[32];
		byte[] key = new byte[8];
		byte[] r = new byte[4];
		
		Util.arrayCopyNonAtomic(papdu.pdata, (short)0, key, (short)0, (short)8);
		Util.arrayCopyNonAtomic(papdu.pdata, (short)9, data, (short)0, (short)(papdu.lc-8));
		
		TestCipher.gmac4(key, data, (short) 9, r);
		Util.arrayCopyNonAtomic(r, (short)0, papdu.pdata, (short)0, (short)4);
		return false;
	}

	private boolean get_sespk() {
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (short)0x18)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		papdu.le = (short)8;
		
		
		byte[] data = new byte[8];
		byte[] key = new byte[16];
		byte[] r = new byte[8];
		
		Util.arrayCopyNonAtomic(papdu.pdata, (short)0, key, (short)0, (short)16);
		Util.arrayCopyNonAtomic(papdu.pdata, (short)16, data, (short)0, (short)8);

		TestCipher.gen_SESPK(key, data, (short)0, (short) 8, r, (short)0);
		Util.arrayCopyNonAtomic(r, (short)0, papdu.pdata, (short)0, (short)8);
		return false;
	}
	
	private boolean Test() {
		byte[] data = new byte[32];
		byte[] key = new byte[]{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		byte[] key4 = new byte[]{1,1,1,1,1,1,1,1};
		byte[] r = new byte[8];
		for (short i = 0; i < 9; i++) {
			data[i] = (byte) (i+1);
		}
		
		short length;
		
		if (papdu.p1==(byte)0x01) {
			TestCipher.xorblock8(key, data, (short) 1);
			Util.arrayCopyNonAtomic(key, (short)0, papdu.pdata, (short)0, (short)8);
		} else if (papdu.p1==(byte)0x02) {
			length= TestCipher.pbocpadding(data, (short)9);
			Util.arrayCopyNonAtomic(data, (short)0, papdu.pdata, (short)0, (short)length);
		}else if (papdu.p1==(byte)0x03) {
			TestCipher.gen_SESPK(key, data, (short)0, (short) 8, r, (short)0);
			Util.arrayCopyNonAtomic(r, (short)0, papdu.pdata, (short)0, (short)8);
		}else if (papdu.p1==(byte)0x04) {
			TestCipher.gmac8(key4, data, (short) 9, r);
			Util.arrayCopyNonAtomic(r, (short)0, papdu.pdata, (short)0, (short)8);
		}else if (papdu.p1==(byte)0x05) {
			EPfile.get_balance(papdu.pdata);
			//Util.arrayCopyNonAtomic(r, (short)0, papdu.pdata, (short)0, (short)8);
		}else if (papdu.p1==(byte)0x06) {
			ISOException.throwIt(EPfile.get_balance(papdu.pdata));
			//Util.arrayCopyNonAtomic(r, (short)0, papdu.pdata, (short)0, (short)8);
		}
		return true;
	}

}
