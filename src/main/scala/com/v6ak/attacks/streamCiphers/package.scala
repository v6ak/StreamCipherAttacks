package com.v6ak.attacks.streamCiphers

import java.util.Base64

object `package`{

  def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] = {
    require(a.length == b.length, "both arrays must be of the same length")
    (a, b).zipped.map((x, y) => (x ^ y).toByte)
  }

  def xor(a: String, b: String, encoding: String): Array[Byte] = xor(a.getBytes(encoding), b.getBytes(encoding))

  def patchStreamCipher(data: Array[Byte], position: Int, patch: Array[Byte]): Array[Byte] = {
    require(data.length >= position+patch.length, "too small data")
    data.take(position) ++ xor(patch, data.drop(position).take(patch.length)) ++ data.drop(position+patch.length)
  }

  def patchPlayAesCtr(ciphertext: String, position: Int, patch: Array[Byte]): String = {
    if(ciphertext.startsWith("2-")){
      val rawOriginalCiphertextWithIV = Base64.getDecoder.decode(ciphertext.drop(2))
      val IVSize = 16 // 128 bits; size of AES block
      val rawPatchedCiphertextWithIV = patchStreamCipher(rawOriginalCiphertextWithIV, position + IVSize, patch)
      "2-" + Base64.getEncoder.encodeToString(rawPatchedCiphertextWithIV)
    }else{
      // 2.4 format without IV could be also supported, but I don't care
      sys.error("only 2.4 format with IV is supported")
    }
  }

}
