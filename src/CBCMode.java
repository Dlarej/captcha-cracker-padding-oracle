import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;


public class CBCMode {
	
	private static final int SHA1_BLOCKSIZE = 64;
	private static final int AES_BLOCKSIZE = 16;
	private static final int HMAC_TAG_SIZE = 20;
	
	private static final String INVALID_MAC_ERROR = "Invalid MAC!";
	private static final String BAD_PADDING_ERROR = "Bad Padding!";
	private static final String SUCCESS = "Success!";
	
	public static byte[] encrypt(byte[] keyEnc, byte[] keyMac, byte[] plaintext) {
		//HMAC-SHA1 algorithm to obtain 20-byte MAC tag T
		byte[] ciphertext = null;
		byte[] MACTag = hmac(keyMac, plaintext);
		byte[] iv = null;
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		try {
			outStream.write(plaintext);
			outStream.write(MACTag);
			int n = outStream.size() % AES_BLOCKSIZE;
			ByteArrayOutputStream paddingString = new ByteArrayOutputStream();
			if (n != 0) {
				for (int i=0; i<(AES_BLOCKSIZE-n); i++) {
					paddingString.write(AES_BLOCKSIZE-n);
				}
			} else {
				for (int i=0; i<AES_BLOCKSIZE; i++) {
					paddingString.write(0x10);
				}
			}
			
			outStream.write(paddingString.toByteArray());
			byte[] paddedMessage = outStream.toByteArray();
			
			/* Debug 
			System.out.println("Padded message before encryption: ");
		    StringBuilder sb = new StringBuilder();
		    for (byte b : paddedMessage) {
		        sb.append(String.format("%02X ", b));
		    }
		    System.out.println(sb.toString());*/
			
			// Generate random 16-byte IV
			iv = new byte[AES_BLOCKSIZE];
			new Random().nextBytes(iv);
			/* Debug 
			StringBuffer buf = new StringBuffer();
			for (byte b : iv) {
				buf.append(String.format("%02X ", b&0xff));
				//System.out.println(b);
			}
			System.out.println(buf.toString());*/
			
			// AES-128 in CBC mode
			ciphertext = aes_cbc_enc(keyEnc, iv, paddedMessage);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		outStream.reset();
		try {
			outStream.write(iv);
			outStream.write(ciphertext);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return outStream.toByteArray();
	}
	
	public static String decrypt(byte[] keyEnc, byte[] keyMac, byte[] ciphertext) {
		String ret = "Success!";
		ByteArrayInputStream inStream = new ByteArrayInputStream(ciphertext);
		byte[] parsedIV = new byte[AES_BLOCKSIZE];
		ByteArrayOutputStream parsedCiphertext = new ByteArrayOutputStream();
		for (int i=0; i<AES_BLOCKSIZE; i++) {
			parsedIV[i] = (byte) inStream.read();
		}
		//System.out.println("parsedIV:");
		/*StringBuffer buf = new StringBuffer();
		for (byte b : parsedIV) {
			buf.append(String.format("%02X", b&0xff));
			//System.out.println(b);
		}
		System.out.println(buf.toString());*/
		while (inStream.available() != 0) {
			parsedCiphertext.write(inStream.read());
		}
		
		byte[] decPaddedMessage = aes_cbc_dec(keyEnc, parsedIV, parsedCiphertext.toByteArray());
		/*buf = new StringBuffer();
		
		System.out.println("decPaddedMessage: ");
		for (byte b : decPaddedMessage) {
			buf.append(String.format("%02X", b&0xff));
			//System.out.println(b);
		}
		System.out.println(buf.toString());*/
		int lastByte = decPaddedMessage[decPaddedMessage.length-1];
		//System.out.println("lastByte: " + lastByte);
		if (lastByte > AES_BLOCKSIZE || lastByte < 1) {
			ret = BAD_PADDING_ERROR;
		}
		for (int i=0; i<lastByte; i++) {
			if (decPaddedMessage[decPaddedMessage.length-1-i] != lastByte) {
				ret = BAD_PADDING_ERROR;
				break;
			}
		}

		return ret;
	}

	private static byte[] hmac(byte[] keyMac, byte[] plaintext) {
		MessageDigest hash = null;
		ByteArrayOutputStream keyStream = new ByteArrayOutputStream();
		try {
			hash = MessageDigest.getInstance("SHA-1", "BC");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}

		try {
			keyStream.write(keyMac);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		if (keyStream.size() > SHA1_BLOCKSIZE) {
			hash.update(keyMac);
			try {
				keyStream.write(hash.digest());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if (keyStream.size() < SHA1_BLOCKSIZE) {
			for (int i=0; i<(SHA1_BLOCKSIZE-keyStream.size()); i++) {
				keyStream.write(0x00);
			}
		}
		/* Debug 
		for (byte b : keyStream.toByteArray()) {
			System.out.println(b);
		}*/
		
		ByteArrayOutputStream opadStream = new ByteArrayOutputStream();
		for (int i=0; i<SHA1_BLOCKSIZE; i++) {
			opadStream.write(0x5c);
		}
		byte[] opad = opadStream.toByteArray();
		ByteArrayOutputStream ipadStream = new ByteArrayOutputStream();
		for (int i=0; i<SHA1_BLOCKSIZE; i++) {
			ipadStream.write(0x36);
		}
		byte[] ipad = opadStream.toByteArray();
		
		byte[] key = keyStream.toByteArray();
		byte[] o_key_pad = new byte[key.length];
		int i = 0;
		for (byte b : o_key_pad) {
			o_key_pad[i] = (byte) (b ^ opad[i++]);
		}
		byte[] i_key_pad = new byte[key.length];
		i = 0;
		for (byte b : i_key_pad) {
			i_key_pad[i] = (byte) (b ^ ipad[i++]);
		}
		
		ByteArrayOutputStream hmacStream = new ByteArrayOutputStream();
		ByteArrayOutputStream padStream = new ByteArrayOutputStream();
		try {
			padStream.write(i_key_pad);
			padStream.write(plaintext);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		try {
			hmacStream.write(o_key_pad);
			hash.update(padStream.toByteArray());
			hmacStream.write(hash.digest());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		hash.update(hmacStream.toByteArray());
		byte[] hmacValue = hash.digest();
		
		return hmacValue;
	}
	
	private static byte[] aes_cbc_enc(byte[] keyEnc, byte[] iv, byte[] paddedMessage) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
			SecretKeySpec skeySpec = new SecretKeySpec(keyEnc, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		ByteArrayInputStream inStream = new ByteArrayInputStream(paddedMessage);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		// Initialize to iv
		byte[] prevCipherBlock = iv;
		byte[] xorBlock;
		for (int i=0; i<(paddedMessage.length/AES_BLOCKSIZE); i++) {
			xorBlock = new byte[AES_BLOCKSIZE];
			for (int j=0; j<AES_BLOCKSIZE; j++) {
				xorBlock[j] = (byte) (inStream.read()^prevCipherBlock[j]);
			}
			// AES-128 encryption
			try {
				// Set prevCipherText to encrypted xorBlock
				prevCipherBlock = cipher.doFinal(xorBlock);
				outStream.write(prevCipherBlock);
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return outStream.toByteArray();
	}

	public static byte[] aes_cbc_dec(byte[] keyEnc, byte[] iv, byte[] ciphertext) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
			SecretKeySpec skeySpec = new SecretKeySpec(keyEnc, "AES");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		ByteArrayInputStream inStream = new ByteArrayInputStream(ciphertext);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		// Initialize to iv
		byte[] prevCipherBlock = iv;
		byte[] currCipherBlock = new byte[AES_BLOCKSIZE];
		byte[] decBlock = new byte[AES_BLOCKSIZE];
		for (int i=0; i<(ciphertext.length/AES_BLOCKSIZE); i++) {
			for (int j=0; j<AES_BLOCKSIZE; j++) {
				currCipherBlock[j] = (byte) inStream.read();
			}
			try {
				decBlock = cipher.doFinal(currCipherBlock);
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
			
			// XOR with prevCipherBlock
			for (int j=0; j<AES_BLOCKSIZE; j++) {
				outStream.write(prevCipherBlock[j]^decBlock[j]);
			}
			
			// Set prevCipherBlock to currCipherBlock (DEEP COPY)
			for (int j=0; j<AES_BLOCKSIZE; j++) {
				prevCipherBlock[j] = currCipherBlock[j];
			}
		}
		
		return outStream.toByteArray();
	}
}
