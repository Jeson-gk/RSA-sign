package test;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.TreeMap;

/**
 * demo-加签名和验证签名核心方法
 * @author k
 *
 */
public class MainSign {

	/**
	 * 签名算法
	 */
	public static final String SIGN_ALGORITHMS = "SHA1WithRSA";
	
	/**
	 * 私钥加签名
	 * @return
	 * @throws Exception 
	 */
	public static TreeMap<String, Object> assembleSign(TreeMap<String, Object> treeMap,String privateStr) throws Exception {
		//数据MD5处理
		String md5 = MainSign.toMD5(treeMap.toString());
		//私钥 对 MD5后的数据 加签
		String packetSignaTure = MainSign.sign(md5, privateStr);
		//增加签名
		treeMap.put("sign", packetSignaTure);
		return treeMap;
	}
	
	/**
	 * 公钥校验签名
	 * @param resultString
	 * @return
	 */
	public static boolean doSignCheck(TreeMap<String,Object> resultTreeMap,String pubStr){
		String sign = resultTreeMap.get("sign").toString();
		resultTreeMap.remove("sign");
		try {
			String resMd5 = MainSign.toMD5(resultTreeMap.toString());
			boolean res = MainSign.doCheck(resMd5, sign, pubStr);
			if(res){
				return res;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return false;
	}
	
	//MD5 32小
	public static String toMD5(String inStr) {
		StringBuffer sb = new StringBuffer();
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(inStr.getBytes());
			byte b[] = md.digest();
			int i;
			for (int offset = 0; offset < b.length; offset++) {
				i = b[offset];
				if (i < 0) {
					i += 256;
				}
				if (i < 16) {
					sb.append("0");
				}
				sb.append(Integer.toHexString(i));
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return sb.toString();
	}
	
	// 私钥加签
	public static String sign(String content, String privateKey) throws Exception {
		PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
		KeyFactory keyf;
		keyf = KeyFactory.getInstance("RSA");
		PrivateKey priKey = keyf.generatePrivate(priPKCS8);
		java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS);
		signature.initSign(priKey);
		signature.update(content.getBytes());
		byte[] signed = signature.sign();
		return Base64.encode(signed);
	}
	
	// 公钥验签
	public static boolean doCheck(String content, String sign, String publicKey) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] encodedKey = Base64.decode(publicKey);
			PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS);
			signature.initVerify(pubKey);
			signature.update(content.getBytes());
			boolean bverify = signature.verify(Base64.decode(sign));
			return bverify;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	//测试
	public static void main(String[] args) throws Exception {
		String privateStr = "私钥";
		TreeMap<String, Object> treeMap = new TreeMap<String, Object>();
		treeMap.put("test", "this is a test;");
		TreeMap<String, Object> signed = MainSign.assembleSign(treeMap, privateStr);
		System.out.println("加签之后：" + signed.toString());
		String publicStr = "公钥";
		Boolean flag = MainSign.doSignCheck(signed, publicStr);
		System.out.println("验签结果：" + flag);
	}
}
