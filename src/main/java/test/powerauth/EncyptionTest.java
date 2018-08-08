package test.powerauth;

import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilBouncyCastle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.xml.encryption.Public;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EncyptionTest {

    private static BaseEncoding base64 = BaseEncoding.base64();
    private static CryptoProviderUtil util;
    private static PowerAuthClientKeyFactory paKeyFact;
    private static KeyGenerator keyGen;
    private static final String APP_KEY_LOCAL="6gJaVZdB6wwfAAVDD5ECWQ==";
    private static final String APP_SECRET_LOCAL="lIQqckjrIVC2TQSVHfcwdA==";


    public static void main(String[] args) throws UnsupportedEncodingException, InvalidKeyException, UnirestException {
        CharSequence  signaturePossessionKey_str = "V7qRp2in2Ps815do4fBxng==";
        CharSequence  signatureKnowledgeKey_str = "sGDn8CJTgClL3kuLuml73A==";
        CharSequence  signatureBiometryKey_str = "dQ4CQPS5aErLM1nVxbpeaQ==";
        String  ACTIVATION_ID_RESPONSE = "7a02c636-bb9e-45c9-894d-2fd59c3a5a7e";

       byte[] signaturePossessionKey_byte = base64.decode(signaturePossessionKey_str);
       byte[] signatureKnowledge_byte = base64.decode(signatureKnowledgeKey_str);
       byte[] signatureBiometry_byte = base64.decode(signatureBiometryKey_str);

        SecretKey signaturePossessionKey  = util.convertBytesToSharedSecretKey(signaturePossessionKey_byte);
        SecretKey signatureKnowledgeKey  = util.convertBytesToSharedSecretKey(signatureKnowledge_byte);
        SecretKey signatureBiometryKey = util.convertBytesToSharedSecretKey(signatureBiometry_byte);


        List<SecretKey> lst = paKeyFact.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY,
                signaturePossessionKey,
                signatureKnowledgeKey,
                signatureBiometryKey);

        byte[] pa_nonce  = keyGen.generateRandomBytes(16);
        byte[] data  = keyGen.generateRandomBytes(16);
        PowerAuthClientSignature paSignature = new PowerAuthClientSignature();
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST","/pa/signature/validate",pa_nonce,data)+"&"+ APP_SECRET_LOCAL;
        String signature = paSignature.signatureForData((signatureBaseString).getBytes("UTF-8"),
                lst,
                1);
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(ACTIVATION_ID_RESPONSE,APP_KEY_LOCAL,signature,"POSSESSION_KNOWLEDGE_BIOMETRY",base64.encode(pa_nonce),"2.0");
        String httpAuhtorizationHeader = header.buildHttpHeader();

        Map<String, String> headers = new HashMap();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put("X-PowerAuth-Authorization", httpAuhtorizationHeader);



        HttpResponse httpResponse = Unirest.
                post("http://localhost:8080/powerauth-restful-server-spring-0.18.0/pa/signature/validate").
                headers(headers).
                asString();


        System.out.println(httpResponse.getBody());


    }


}
