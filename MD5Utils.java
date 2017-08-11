package com.isoftstone.insurance.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Utils {
	public static String getEncryption(String token) {
        String result = "";
        if (token != null) {
            try {
                // 指定加密的方式为MD5
                MessageDigest md = MessageDigest.getInstance("MD5");
                // 进行加密运算
                byte bytes[] = md.digest(token.getBytes());
                for (int i = 0; i < bytes.length; i++) {
                    // 将整数转换成十六进制形式的字符串 这里与0xff进行与运算的原因是保证转换结果为32位
                    String str = Integer.toHexString(bytes[i] & 0xFF);
                    if (str.length() == 1) {
                        str += "f";
                    }
                    result += str;
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return result.toLowerCase();
    }
	
	public static String md5Encode(String token){  
	      MessageDigest md5 = null;  
	      try{  
	          md5 = MessageDigest.getInstance("MD5");  
	      }catch(Exception e){  
	          System.out.println(e.toString());  
	          e.printStackTrace();  
	          return "";  
	      }  
	      byte[] byteArray = null;  
	      try {  
	          byteArray = token.getBytes("UTF-8");  
	      } catch (UnsupportedEncodingException e) {  
	          e.printStackTrace();  
	      }  
	      byte[] md5Bytes = md5.digest(byteArray);  
	      StringBuffer hexValue = new StringBuffer();  
	      for(int i=0;i<md5Bytes.length;i++){  
	          int val = md5Bytes[i] & 0xff;  
	          if(val<16){  
	              hexValue.append("0");  
	          }  
	          hexValue.append(Integer.toHexString(val));  
	      }  
	      return hexValue.toString();  
	  }  

	public static void main(String[] args) {
		String md5Encode = md5Encode("F322ABDDFA01");
		System.out.println(md5Encode);
	}
}
