package jm.oauth.messagesigner

import jm.oauth.MessageSigner
import net.oauth.OAuth.{percentEncode => encode}
import org.apache.commons.codec.digest.DigestUtils //nicer implementation to work with than java.security.MessageDigest
import org.apache.commons.codec.binary.Hex
import org.apache.commons.codec.binary.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.collection.immutable.SortedMap

class HmacSha1 extends MessageSigner{
  //May compact the url, method, and params to a single object
  /**
   * Returns a base64 encoded string to use as an OAuth signature
   * 
   * @param key String - signing key
   * @param token String - signing token
   * @param method String - HTTP request method that will be used
   * @param url String - URL that the request will be made to
   * @param Map[String, String]() - map of key/value pairs of params that need to be included in the signature
   * 
   * @return base64 encoded String
   */
  override def createSignature(key: String, token: String, method: String,
                               url: String, requestParams: Map[String, String]): String = {
    val sigString = method.toUpperCase +
                    "&" + encode(url) +
                    "&" + encode(requestParams.toList.sortWith( _._1 < _._1 ).map{
                                   case (k,v) => k + "=" + v
                                 }.mkString("&"))
    new String(Base64.encodeBase64(generateSHA1Hash(sigString, key, token)))
  }
  
  /**
   * Generates a SHA1 hash from the token and key
   */
  def generateSHA1Hash(value: String, key: String, token: String): Array[Byte] = {
    val keyString = encode(key) + "&" + (if(token != null) token else "")
    val keyBytes = keyString.getBytes("US-ASCII")
    val signingKey = new SecretKeySpec(keyBytes, "HmacSHA1")
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(signingKey)
    mac.doFinal(value.getBytes("US-ASCII"))
  }
}