package jm.oauth

import jm.oauth.OAuth
import jm.oauth.messagesigner._

trait MessageSigner {
  def createSignature(key: String, token: String, method: String, url: String, requestParams: Map[String, String]): String = {
    //Should throw an exception as if we hit this, then it's not really implemented.
    return null
  }
}

object MessageSigner {
   /**
   * Simple factory for MessageSigner objects based on this.signatureMethod value
   */
  def signatureFactory(signature: String): MessageSigner = {
    signature match {
      case OAuth.HMAC_SHA1 => new HmacSha1
      case OAuth.PLAINTEXT => new Plaintext
    }
  }
}