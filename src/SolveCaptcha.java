import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class SolveCaptcha {
	
	private static String captcha;
	private static byte[] ciphertext;
	private static byte[] keyMac;
	private static byte[] keyEnc;
	
	private static byte[] plaintext;
	
	private static final int AES_BLOCKSIZE = 16;
	
	private static final String INVALID_MAC_ERROR = "Invalid MAC!";
	private static final String BAD_PADDING_ERROR = "Bad Padding!";
	private static final String SUCCESS = "Success!";
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		if (args.length != 1) {
			System.out.println("Usage: <6-character CAPTCHA>");
		}
		captcha = args[0];
		// Produce random byte arrays for keyMac, and keyEnc
		keyEnc = new byte[AES_BLOCKSIZE];
		new Random().nextBytes(keyEnc);
		keyMac = new byte[AES_BLOCKSIZE];
		new Random().nextBytes(keyMac);
		// Simulate server encrypting captcha
		ciphertext = CBCMode.encrypt(keyEnc, keyMac, captcha.getBytes());
		// Encoded ciphertext for captcha to make URL safe
		String encodedCiphertext = Base64.toBase64String(ciphertext);
		// Simulate conversion back into byte code
		byte[] decodedCiphertext = (byte[]) Base64.decode(encodedCiphertext);
		
		plaintext = new byte[decodedCiphertext.length-AES_BLOCKSIZE];
		byte intermediateState[] = new byte[AES_BLOCKSIZE];
		
		// Begin Padding Oracle Attack
		// Perform last byte attack on each block
		for (int i=0; i<decodedCiphertext.length/AES_BLOCKSIZE-1; i++) {
			// For every block, check for correct padding 0x01, 0x02 0x02, etc.
			byte[] cipherBlock = new byte[AES_BLOCKSIZE];
			byte[] prevCipherBlock = new byte[AES_BLOCKSIZE];
			for (int _i=0; _i<AES_BLOCKSIZE; _i++) {
				cipherBlock[_i] = decodedCiphertext[(decodedCiphertext.length/AES_BLOCKSIZE-(i+1))*AES_BLOCKSIZE+_i];
				prevCipherBlock[_i] = decodedCiphertext[(decodedCiphertext.length/AES_BLOCKSIZE-(i+2))*AES_BLOCKSIZE+_i];
			}
			// Calculate P[AES_BLOCKSIZE-j-1] and store
			for (int j=0; j<AES_BLOCKSIZE; j++) {
				/* CHANGE CHANGE CHANGE */
				// _cipherBlock is the chosen ciphertext
				byte[] _cipherBlock = new byte[AES_BLOCKSIZE];
				// Choose decodedCiphertext[0..AES_BLOCKSIZE-j-2] to be random bytes
				new Random().nextBytes(_cipherBlock);
				// Choose decodedCiphertext[AES_BLOCKSIZE-j-1] to be 0x00
				_cipherBlock[AES_BLOCKSIZE-j-1] = 0x00;
				// Choose decodedCiphertext[AES_BLOCKSIZE-j..AES_BLOCKSIZE-1] to be chosen
				// such that P2'[AES_BLOCKSIZE-j..AES_BLOCKSIZE-1] == 0x(j+1)
				if (j != 0) {
					// Satisfy conditions
					for (int k=AES_BLOCKSIZE-j; k<AES_BLOCKSIZE; k++) {
						_cipherBlock[k] = (byte) (intermediateState[k]^(j+1)); 
					}
				}
				
				ByteArrayOutputStream outStream = new ByteArrayOutputStream();
				outStream.write(_cipherBlock);
				outStream.write(cipherBlock);
				byte[] concatBlock = outStream.toByteArray();

				while (true) {
					// Check for valid padding and MAC
					String status = CBCMode.decrypt(keyEnc, keyMac, concatBlock);
					//System.out.println(status);
					if (status != SUCCESS) {
						concatBlock[AES_BLOCKSIZE-j-1]++;
					} else {
						break;
					}
				}
				
				// Find out Plaintext[AES_BLOCKSIZE-j-1] using cipherBlock
				for (int k=0; k<AES_BLOCKSIZE; k++) {
					_cipherBlock[k] = concatBlock[k];
				}
				intermediateState[AES_BLOCKSIZE-j-1] = (byte) (_cipherBlock[AES_BLOCKSIZE-j-1]^(j+1));
				plaintext[(AES_BLOCKSIZE-j-1)+AES_BLOCKSIZE*(decodedCiphertext.length/AES_BLOCKSIZE-1-i)-AES_BLOCKSIZE] = 
						(byte) (prevCipherBlock[AES_BLOCKSIZE-j-1]^intermediateState[AES_BLOCKSIZE-j-1]);
			}
		}
		String decryptedMessage = "";
		try {
			decryptedMessage = new String(plaintext, "ASCII");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		String captcha = decryptedMessage.substring(0,6);
		System.out.println("CaptchaID: " + captcha);
	}
}
