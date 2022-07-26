/*
 * Copyright 2014 Google Inc.
 * Copyright 2016 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import static org.junit.Assert.assertEquals;

import org.bitcoinj.script.*;
import org.bitcoinj.signers.DetachedTransactionSigner;
import org.bouncycastle.util.encoders.Hex;
import org.junit.*;

import java.util.*;

public class DetachedTransactionSignerTest {
  @Test
  public void testSignP2WPKH(){
      String rawTx = "0200000001f5d496b50827815316e3b15f54c7d970d031ef6024e7e609972ebf44c08c1c130000000000fdffffff0240420f0000000000160014b8d5dda99143f7493608c54cf50f27e457f08439c0943f2901000000160014adf9a9852767c94457cf50052cb110b9338cd0f900000000";
      Transaction t1 = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_TESTNET), Hex.decode(rawTx));
      String wif_private = "cSXrBnbkSNqMQCDz1X4FYVHBgf285gLYagWsh1KDLHVT9XWtbiuW";
      byte [] wif = Base58.decodeChecked(wif_private);
      ECKey key = ECKey.fromPrivate(Arrays.copyOfRange(wif, 1, wif.length-1), true);
      Script s = ScriptBuilder.createP2WPKHOutputScript(key);

      DetachedTransactionSigner.sign(t1, Arrays.asList(key), Arrays.asList(s));

      byte [] serial_tx = t1.bitcoinSerialize();
      String encoded_tx = Hex.toHexString(serial_tx);
      assertEquals(encoded_tx, "02000000000101f5d496b50827815316e3b15f54c7d970d031ef6024e7e609972ebf44c08c1c130000000000fdffffff0240420f0000000000160014b8d5dda99143f7493608c54cf50f27e457f08439c0943f2901000000160014adf9a9852767c94457cf50052cb110b9338cd0f902483045022100e21ceb285a977a210fd9757b799d366a11f2c3aa08cb79b15c08a7b7805dcd3a0220502627596792764ead72e66a97abedbc57e306261ac3c92959e7e7f060c8d553012102b575cb96fae641a1804ec1023984e3849f579f9092ab5e09a0f839b91608b57000000000");
  }

  @Test
  public void testSignP2PKH(){
    String rawTx = "0200000001f5d496b50827815316e3b15f54c7d970d031ef6024e7e609972ebf44c08c1c130000000000fdffffff0240420f0000000000160014b8d5dda99143f7493608c54cf50f27e457f08439c0943f2901000000160014adf9a9852767c94457cf50052cb110b9338cd0f900000000";
    Transaction t1 = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_TESTNET), Hex.decode(rawTx));
    String wif_private = "cSXrBnbkSNqMQCDz1X4FYVHBgf285gLYagWsh1KDLHVT9XWtbiuW";
    byte [] wif = Base58.decodeChecked(wif_private);
    ECKey key = ECKey.fromPrivate(Arrays.copyOfRange(wif, 1, wif.length-1), true);
    Script s = ScriptBuilder.createP2PKHOutputScript(key);

    DetachedTransactionSigner.sign(t1, Arrays.asList(key), Arrays.asList(s));

    byte [] serial_tx = t1.bitcoinSerialize();
    String encoded_tx = Hex.toHexString(serial_tx);
    assertEquals(encoded_tx, "0200000001f5d496b50827815316e3b15f54c7d970d031ef6024e7e609972ebf44c08c1c13000000006b483045022100ae37bcd4b00d2b8af735f78cad0755452da8b534d8e50f133a7c1c352ae42eaa022018afd994cc4b2bf1f876dcde56965fd1fcb5cc16151d1a6e2378e7323193c7bd012102b575cb96fae641a1804ec1023984e3849f579f9092ab5e09a0f839b91608b570fdffffff0240420f0000000000160014b8d5dda99143f7493608c54cf50f27e457f08439c0943f2901000000160014adf9a9852767c94457cf50052cb110b9338cd0f900000000");
  }
}
