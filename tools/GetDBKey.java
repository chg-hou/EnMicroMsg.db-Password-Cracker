 // copy from https://bbs.pediy.com/thread-250714.htm
 // copyright @ newx
 
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.util.HashMap;
public class GetDBKey {
 public static void main(String[] args) {
  try {
   ObjectInputStream in = new ObjectInputStream(new FileInputStream("CompatibleInfo.cfg"));
   Object DL = in.readObject();
   HashMap hashWithOutFormat = (HashMap) DL;
   String s = String.valueOf(hashWithOutFormat.get(Integer.valueOf(258))); // 取手机的IMEI
   System.out.println("IMEI:"+s);
   ObjectInputStream in1 = new ObjectInputStream(new FileInputStream("systemInfo.cfg"));
   Object DJ = in1.readObject();
   HashMap hashWithOutFormat1 = (HashMap) DJ;
   String t = String.valueOf(hashWithOutFormat1.get(Integer.valueOf(1))); // 取微信的uin
   System.out.println("uin:"+t);
   s = s + t; //合并到一个字符串
   s = encode(s); // MD5
   System.out.println("密码是 : " + s.substring(0, 7));
   in.close();
   in1.close();
  } catch (Exception e) {
   e.printStackTrace();
  }
 }
 public static String encode(String content)
  {
   try {
    MessageDigest digest = MessageDigest.getInstance("MD5");
    digest.update(content.getBytes());
    return getEncode32(digest);
    }
   catch (Exception e)
   {
    e.printStackTrace();
   }
   return null;
  }
  private static String getEncode32(MessageDigest digest)
  {
   StringBuilder builder = new StringBuilder();
   for (byte b : digest.digest())
   {
    builder.append(Integer.toHexString((b >> 4) & 0xf));
    builder.append(Integer.toHexString(b & 0xf));
   }
    return builder.toString();
  
  }
}
