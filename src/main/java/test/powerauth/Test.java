package test.powerauth;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.provider.CryptoProviderUtilBouncyCastle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;


import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Test {

    public static void main(String[] args) throws Exception {
//        Security.addProvider(new BouncyCastleProvider());
//
//
//        byte[] publicKey = org.bouncycastle.util.encoders.Base64.
//                decode("BNwXcpJUN7eY+4NwS1bfEygCPby+O6UEaIhZyVJipbarOcorUB0F3ALxpuurd3HEH5XpEAk9ZnfT9c1JQFCOv6U=");
//
//
//        // convert string to PublicKey
//        CryptoProviderUtilBouncyCastle cryptoProviderUtilBouncyCastle = new CryptoProviderUtilBouncyCastle();
//        PublicKey pKey =cryptoProviderUtilBouncyCastle.convertBytesToPublicKey(publicKey);
////
//
////        byte[] str = cryptoProviderUtilBouncyCastle.convertPublicKeyToBytes(pKey);
////
////
////        String fin =org.bouncycastle.util.encoders.Base64.toBase64String(str);
////        System.out.println(fin);
//
//       KeyGenerator arr = new KeyGenerator();
//       byte[] str = arr.generateRandomBytes(16);
//        System.out.println(org.bouncycastle.util.encoders.Base64.toBase64String(str));
//
////        String keyString = org.bouncycastle.util.encoders.Base64.encodeToString(masterPublicKey.getEncoded());
//
//
//        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
//        byte[] strArr = "ROXFemPcwtKVxgyhbv/cTA==".getBytes();


        String APPLICATION_KEY = "6gJaVZdB6wwfAAVDD5ECWQ==";
        byte[] appKeyAr1 = APPLICATION_KEY.getBytes();
        String appKeyStr1 = Base64.toBase64String(appKeyAr1);

        String google1 = BaseEncoding.base64().encode(appKeyAr1);

        byte[] appKeyAr2 = Base64.decode(APPLICATION_KEY);
        String appKeyStr2  = Base64.toBase64String(appKeyAr2);

        String google2 = BaseEncoding.base64().encode(appKeyAr2);

        System.out.println(appKeyAr1 == appKeyAr2);
        System.out.println(appKeyStr1 + "======" + appKeyStr2);
        System.out.println(google1 + "======" + google2);



    }
}
