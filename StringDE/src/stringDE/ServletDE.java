package stringDE;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Servlet implementation class ServletDE
 */
@WebServlet(description = "Decrypt or encrypt strings with given keys and type of op.", urlPatterns = { "/ServletDE" })
public class ServletDE extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public ServletDE() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.setContentType("text/html");
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
//		request.setCharacterEncoding(StandardCharsets.UTF_8.name());
		String key = request.getParameter("key");
		String content = request.getParameter("content");
		int type = Integer.parseInt(URLDecoder.decode(request.getParameter("type"), StandardCharsets.UTF_8.name()));
		key = URLDecoder.decode(key, StandardCharsets.UTF_8.name());
		content = URLDecoder.decode(content, StandardCharsets.UTF_8.name());

		String rlst = null;
		if(type == 1) {
			content = content.replaceAll(" ", "+");
			rlst = decrypt4Aes2Str(key, content);
		}
		else if(type == 2) {
			rlst = encrypt4Aes(key, content);
	/*		int i = 77;
			int count = 1;
			while(i-1 < rlst.length()) {
				rlst = rlst.substring(0, 76*count) + rlst.substring(i);
				count++;
				i += 76;
			}*/
		}
		PrintWriter out = response.getWriter();
		out.println(rlst);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

	public static final String SHA_1 = "SHA-1";
	static final String AES = "AES";
	static final String AES_ECB_PKCS5_PADDING = "AES/ECB/PKCS5Padding";
	static final String SHA1_PRNG = "SHA1PRNG";
	public static final String CHARSET_UTF8 = "UTF-8";
	public static final String SHA_256 = "SHA-256";

	/**
	 * AES算法解密入口
	 */
	public static String decrypt4Aes2Str(String key, String content)  {
		String result = null;
		byte[] dst = null;
		try {
			dst = decrypt4Aes(content, key);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (null != dst) {
			try {
				result = new String(dst, CHARSET_UTF8);
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return result;
	}

	private static byte[] decrypt4Aes(String content, String key) throws IOException, IllegalBlockSizeException,
	InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] src = base64decode(content);
		return decryptMode(src, key);
	}

	private static byte[] decryptMode(byte[] src, String key) throws NoSuchPaddingException, NoSuchAlgorithmException,
	BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		Cipher cip = Cipher.getInstance(AES);
		cip.init(Cipher.DECRYPT_MODE, getSecretKey(key));
		return cip.doFinal(src);
	}


	//将BASE64编码的字符串s进行解码
	private static byte[] base64decode(String s) throws IOException {
		return s == null ? null : new BASE64Decoder().decodeBuffer(s);
	}


	/**
	 * AES加密算法入口
	 *
	 * @param content 加密前数据
	 */
	public static String encrypt4Aes(String key, String content) {
		byte[] src = null;
		try {
			src = content.getBytes(CHARSET_UTF8);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//加密
		byte[] bytOut = null;
		try {
			bytOut = encryptMode(src, key);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException
				| IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return base64encode(bytOut);
	}

	/**
	 * AES 加密实现
	 *
	 * @param src 加密前数据字节
	 * @return
	 */

	private static byte[] encryptMode(byte[] src, String key) throws NoSuchPaddingException, NoSuchAlgorithmException,
	InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cip = Cipher.getInstance(AES);
		cip.init(Cipher.ENCRYPT_MODE, getSecretKey(key));
		return cip.doFinal(src);

	}


	//将s进行BASE64编码
	private static String base64encode(byte[] src) {
		return src == null ? null : new BASE64Encoder().encode(src);
	}


	private static SecretKey getSecretKey(String key) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException {
		byte[] keybyte = getKeyByStr(key);
		SecureRandom secureRandom = SecureRandom.getInstance(SHA1_PRNG);
		secureRandom.setSeed(keybyte);
		KeyGenerator keygen = KeyGenerator.getInstance(AES);
		keygen.init(secureRandom);
		return keygen.generateKey();
	}


	private static byte[] getKeyByStr(String str) {
		byte[] bRet = new byte[str.length() / 2];
		for (int i = 0; i < str.length() / 2; i++) {
			Integer itg = 16 * getChrInt(str.charAt(2 * i)) + getChrInt(str.charAt(2 * i + 1));
			bRet[i] = itg.byteValue();
		}
		return bRet;
	}


	private static int getChrInt(char chr) {
		int iRet = 0;
		if (chr == "0".charAt(0)) iRet = 0;
		if (chr == "1".charAt(0)) iRet = 1;
		if (chr == "2".charAt(0)) iRet = 2;
		if (chr == "3".charAt(0)) iRet = 3;
		if (chr == "4".charAt(0)) iRet = 4;
		if (chr == "5".charAt(0)) iRet = 5;
		if (chr == "6".charAt(0)) iRet = 6;
		if (chr == "7".charAt(0)) iRet = 7;
		if (chr == "8".charAt(0)) iRet = 8;
		if (chr == "9".charAt(0)) iRet = 9;
		if (chr == "A".charAt(0)) iRet = 10;
		if (chr == "B".charAt(0)) iRet = 11;
		if (chr == "C".charAt(0)) iRet = 12;
		if (chr == "D".charAt(0)) iRet = 13;
		if (chr == "E".charAt(0)) iRet = 14;
		if (chr == "F".charAt(0)) iRet = 15;
		return iRet;
	}

	/**
	 * 散列
	 */
	public static String encryptPwd(String strSrc, String encName, String charset) throws
	UnsupportedEncodingException {
		if (strSrc == null || encName == null) {
			return null;
		}
		MessageDigest messageDigest;
		String strDes;
		byte[] bt = strSrc.getBytes(charset);
		try {
			messageDigest = MessageDigest.getInstance(encName);
			messageDigest.update(bt);
			strDes = bytes2Hex(messageDigest.digest()); // to HexString
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		return strDes;
	}


	private static String bytes2Hex(byte[] bts) {
		StringBuilder des = new StringBuilder();
		String tmp;
		for (byte bt : bts) {
			tmp = (Integer.toHexString(bt & 0xFF));
			if (tmp.length() == 1) {
				des.append("0");
			}
			des.append(tmp);
		}
		return des.toString();
	}
}
