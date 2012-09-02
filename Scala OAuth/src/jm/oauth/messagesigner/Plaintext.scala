package jm.oauth.messagesigner

import jm.oauth.MessageSigner

class Plaintext extends MessageSigner {
	override def createSignature(key: String, token: String, method: String,
                               url: String, requestParams: Map[String, String]): String = {
	  key + "&" + (if(token != null) token else "")
	}
}