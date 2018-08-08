package test.powerauth;

import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.*;
import io.getlime.push.client.MobilePlatform;
import io.getlime.push.client.PushServerClient;
import io.getlime.push.client.PushServerClientException;
import io.getlime.push.model.entity.PushMessage;
import io.getlime.push.model.entity.PushMessageAttributes;
import io.getlime.push.model.entity.PushMessageBody;
import io.getlime.push.model.response.ServiceStatusResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.encryptor.ClientNonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.PersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilBouncyCastle;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.encryption.EncryptorFactory;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponse;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class NewTest {
    private static BaseEncoding base64 = BaseEncoding.base64();
    private static final String USER_ID = "2";
    private static final Long APP_ID = 4l;
    private static final Long APP_ID_LOCAL= 2l;
    private static final String APP_KEY_LOCAL="6gJaVZdB6wwfAAVDD5ECWQ==";
    private static final String APP_SECRET_LOCAL="lIQqckjrIVC2TQSVHfcwdA==";
    private static final String APP_KEY = "YBg9wh/59WBQcXCqiNKnPA==";
    private static final String APP_SECRET = "YSzSbatSC/PSw9eKMq0PAw==";
    private static final String KEY_SERVER_MASTER_PUBLIC_LOCAL = "BGAv1wkHYt29DFGkmXVp4Ew1C54UNkg9nTfEGPulNfdmfkpB4aDqp9Tqy8hzH3or8zDoUkFWJkf/TFJI3FwUxDI=";
    private static final  KeyGenerator keyGen = new KeyGenerator();
    static PowerAuthWebServiceConfiguration config = new PowerAuthWebServiceConfiguration();
    static PowerAuthServiceClient client = config.powerAuthClient(config.marshaller());
    private static HttpServletRequest request;
    private static PowerAuthAuthenticationProvider authenticationProvider;




    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // 1 - 4
        InitActivationResponse responseInit = initiateActivation();
        // 5 - 6 optional
        String activationId = responseInit.getActivationId();
        String ACTIVATION_ID_SHORT = responseInit.getActivationIdShort();
        String ACTIVATION_OTP = responseInit.getActivationOTP();
        String ACTIVATION_ID = responseInit.getActivationId();


        String activationID = exchangeKey(ACTIVATION_ID_SHORT, ACTIVATION_OTP,ACTIVATION_ID);
//


        System.out.println("Activation ID :" + activationID);


    }




    private static InitActivationResponse initiateActivation() {
        InitActivationRequest requestInit = new InitActivationRequest();
        requestInit.setUserId(USER_ID);
        requestInit.setApplicationId(APP_ID_LOCAL);
        requestInit.setMaxFailureCount(3l);
        InitActivationResponse responseInit = client.initActivation(requestInit);
        return responseInit;
    }

    public static String exchangeKey(String ACTIVATION_ID_SHORT, String ACTIVATION_OTP, String ACTIVATION_ID)
            throws Exception {


        CryptoProviderUtilBouncyCastle util = new CryptoProviderUtilBouncyCastle();

        // 7. generate device key pair
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(new CryptoProviderUtilBouncyCastle());
        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        KeyPair deviceKeyPair = generateKeyPair();
        PrivateKey KEY_DEVICE_PRIVATE = deviceKeyPair.getPrivate();
        PublicKey KEY_DEVICE_PUBLIC = deviceKeyPair.getPublic();

//        System.out.println(base64.encode(util.convertPublicKeyToBytes(KEY_DEVICE_PUBLIC)));
        GetApplicationDetailResponse appRes = client.getApplicationDetail(2l);



        // 8. client send request: ACTIVATION_ID_SHORT, ACTIVATION_NONCE, C_KEY_DEVICE_PUBLIC, KEY_EPHEMERAL_PUBLIC
        KeyPair ephKeyPair = generateKeyPair();
        PrivateKey KEY_EPH_PRIVATE = ephKeyPair.getPrivate();
        PublicKey KEY_EPH_PUBLIC = ephKeyPair.getPublic();

        String KEY_EPH_PUBLIC_STR = base64.encode(util.convertPublicKeyToBytes(KEY_EPH_PUBLIC));

        // convert string to PublicKey

        byte[] publicBytes = BaseEncoding.base64().decode(KEY_SERVER_MASTER_PUBLIC_LOCAL);
        PublicKey masterPublicKey = util.convertBytesToPublicKey(publicBytes);

        //ACTIVATION_NONCE
        byte[] ACTIVATION_NONCE = clientActivation.generateActivationNonce();
        String ACTIVATION_NONCE_STR = base64.encode(ACTIVATION_NONCE);


        //C_KEY_DEVICE_PUBLIC
        byte[] C_KEY_DEVICE_PUBLIC = clientActivation.encryptDevicePublicKey(
                KEY_DEVICE_PUBLIC, KEY_EPH_PRIVATE,
                masterPublicKey, ACTIVATION_OTP,
                ACTIVATION_ID_SHORT, ACTIVATION_NONCE);
        String C_KEY_DEVICE_PUBLIC_STR = base64.encode(C_KEY_DEVICE_PUBLIC);


        //APPLICATION_SIGNATURE
        byte[] APPLICATION_SIGNATURE = clientActivation.
                computeApplicationSignature(
                        ACTIVATION_ID_SHORT,
                        ACTIVATION_NONCE,
                        C_KEY_DEVICE_PUBLIC,
                        Base64.decode(APP_KEY_LOCAL),
                        Base64.decode(APP_SECRET_LOCAL));
        String APP_SIG_STR = base64.encode(APPLICATION_SIGNATURE);


          PrepareActivationRequest prepareActivationRequest = new PrepareActivationRequest();
        prepareActivationRequest.setActivationName("My Iphone");
        prepareActivationRequest.setActivationIdShort(ACTIVATION_ID_SHORT);
        prepareActivationRequest.setActivationNonce(ACTIVATION_NONCE_STR);
        prepareActivationRequest.setApplicationSignature(APP_SIG_STR);
        prepareActivationRequest.setEncryptedDevicePublicKey(C_KEY_DEVICE_PUBLIC_STR);
        prepareActivationRequest.setEphemeralPublicKey(KEY_EPH_PUBLIC_STR);
        prepareActivationRequest.setApplicationKey(APP_KEY_LOCAL);



          PrepareActivationResponse response = client.prepareActivation(prepareActivationRequest);

        String activationID = response.getActivationId();


        String ENCRYPTED_SERVER_KEY_SIGNATURE_RESPONSE = response.getEncryptedServerPublicKeySignature();
        byte[] ENCRYPTED_SERVER_KEY_SIGNATURE_BYTE = base64.decode(ENCRYPTED_SERVER_KEY_SIGNATURE_RESPONSE);

        //C_SERVER_PUBLIC_KEY
        String ENCRYPTED_SERVER_PUBLICKEY_RESPONSE = response.getEncryptedServerPublicKey();
        byte[] C_KEY_SERVER_PUBLIC= base64.decode(ENCRYPTED_SERVER_PUBLICKEY_RESPONSE);

        //SERVER_EPH_KEY
        String EPH_PUBLIC_KEY_RESPONSE = response.getEphemeralPublicKey();
        byte[]  EPH_PUPLIC_KEY_BYTE = base64.decode(EPH_PUBLIC_KEY_RESPONSE);

        String ACTIVATION_NONCE_RESPONSE = response.getActivationNonce();
        byte[] ACTIVATION_NONCE_BYTE = base64.decode(ACTIVATION_NONCE_RESPONSE);

        PublicKey EPH_PUBLIC_KEY = util.convertBytesToPublicKey(EPH_PUPLIC_KEY_BYTE);

        boolean isTrue = clientActivation.verifyServerDataSignature(activationID,C_KEY_SERVER_PUBLIC,ENCRYPTED_SERVER_KEY_SIGNATURE_BYTE,masterPublicKey);
        System.out.println("verifyServerDataSignature:" + isTrue);
            PublicKey SERVER_PUBLIC_KEY = clientActivation.
                    decryptServerPublicKey(
                            C_KEY_SERVER_PUBLIC,
                            KEY_DEVICE_PRIVATE,
                            EPH_PUBLIC_KEY,
                            ACTIVATION_OTP,
                            ACTIVATION_ID_SHORT,
                            ACTIVATION_NONCE_BYTE);



        //Class use for generate keys
        PowerAuthClientKeyFactory paKeyFact = new PowerAuthClientKeyFactory();

        // KEY_MASTER_SECRET
        SecretKey KEY_MASTER_SECRET = paKeyFact.generateClientMasterSecretKey(KEY_DEVICE_PRIVATE,SERVER_PUBLIC_KEY);


        byte[] salt = keyGen.generateRandomBytes(16);

        //SIGNATURE_KEY ( generate by client )
        SecretKey TRANSPORT_KEY = paKeyFact.generateServerTransportKey(KEY_MASTER_SECRET);
        SecretKey KEY_POSSESSION_SIGNATURE = paKeyFact.generateClientSignaturePossessionKey(KEY_MASTER_SECRET);

        SecretKey KEY_KNOWLEDGE_SIGNATURE_UNC = paKeyFact.generateClientSignatureKnowledgeKey(KEY_MASTER_SECRET);
        byte[] KEY_KNOWLEDGE_SIGNATURE_BYTE_ENC = EncryptedStorageUtil.storeSignatureKnowledgeKey("123".toCharArray(),KEY_KNOWLEDGE_SIGNATURE_UNC,salt,keyGen);
        SecretKey KEY_KNOWLEDGE_SIGNATURE = EncryptedStorageUtil.getSignatureKnowledgeKey("123".toCharArray(), KEY_KNOWLEDGE_SIGNATURE_BYTE_ENC, salt, keyGen);
        SecretKey KEY_BIOMETRY_SIGNATURE = paKeyFact.generateClientSignatureBiometryKey(KEY_MASTER_SECRET);
//
        byte[] KEY_POSSESSION_SIGNATURE_BYTE = util.convertSharedSecretKeyToBytes(KEY_POSSESSION_SIGNATURE);
        byte[] KEY_KNOWLEDGE_SIGNATURE_BYTE = util.convertSharedSecretKeyToBytes(KEY_KNOWLEDGE_SIGNATURE);
        byte[] KEY_BIOMETRY_SIGNATURE_BYTE = util.convertSharedSecretKeyToBytes(KEY_BIOMETRY_SIGNATURE);

        String KEY_POSSESSION_SIGNATURE_STR = base64.encode(util.convertSharedSecretKeyToBytes(KEY_POSSESSION_SIGNATURE));
        String KEY_KNOWLEDGE_SIGNATURE_STR = base64.encode(util.convertSharedSecretKeyToBytes(KEY_KNOWLEDGE_SIGNATURE));
        String KEY_BIOMETRY_SIGNATURE_STR = base64.encode(util.convertSharedSecretKeyToBytes(KEY_BIOMETRY_SIGNATURE));


        SecretKey signaturePossessionKey  = util.convertBytesToSharedSecretKey(KEY_POSSESSION_SIGNATURE_BYTE);
        SecretKey signatureKnowledgeKey  = util.convertBytesToSharedSecretKey(KEY_KNOWLEDGE_SIGNATURE_BYTE);
        SecretKey signatureBiometryKey = util.convertBytesToSharedSecretKey(KEY_BIOMETRY_SIGNATURE_BYTE);

        // GET ACTIVATION STATUS
        String ACTIVATION_ID_RESPONSE = response.getActivationId();
        System.out.println("ACTIVATION_ID_RESPONSE: " +ACTIVATION_ID_RESPONSE);

        String ActivationID = commitActivation(ACTIVATION_ID_RESPONSE);
        PowerAuthClientSignature paSignature = new PowerAuthClientSignature();

        List<SecretKey> lst = paKeyFact.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY,
                signaturePossessionKey,
                signatureKnowledgeKey,
                signatureBiometryKey);

        byte[] pa_nonce  = keyGen.generateRandomBytes(16);
        byte[] data  = keyGen.generateRandomBytes(16);

        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST","/pa/signature/validate", pa_nonce, data)+"&"+ APP_SECRET_LOCAL;
        String signature = paSignature.signatureForData((signatureBaseString).getBytes("UTF-8"),
                lst,
                1);

        System.out.println(signature);
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(ActivationID,APP_KEY_LOCAL,signature,"POSSESSION_KNOWLEDGE_BIOMETRY",base64.encode(pa_nonce),"2.1");
        String httpAuhtorizationHeader = header.buildHttpHeader();

        Map<String, String> headers = new HashMap();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put("X-PowerAuth-Authorization", httpAuhtorizationHeader);

        HttpResponse httpResponse = Unirest.
                post("http://localhost:8080/powerauth-restful-server-spring-0.18.0/pa/signature/validate").
                headers(headers).
                body(data).
                asString();

        System.out.println(httpResponse.getHeaders());
        System.out.println(httpResponse.getBody());


//        byte[] pa_nonce_2 = keyGen.generateRandomBytes(16);
//        String signatureBaseString2 = (new URI("/pa/signature/validate/")).getRawQuery();
//        String pa_signature2 = PowerAuthRequestCanonizationUtils.canonizeGetParameters(signatureBaseString2);
//        byte[] dataFileBytes = pa_signature2.getBytes("UTF-8");
//
//        String signatureBaseString3 = PowerAuthHttpBody.
//                getSignatureBaseString("GET","/pa/signature/validate",
//                        pa_nonce_2, dataFileBytes) + "&" + APP_SECRET_LOCAL;
//
//        List<SecretKey> lst2 = paKeyFact.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY,
//                signaturePossessionKey,
//                signatureKnowledgeKey,
//                signatureBiometryKey);
//
//        String signature2 = paSignature.signatureForData(signatureBaseString3.getBytes("UTF-8"),lst2,1);
//
//        PowerAuthSignatureHttpHeader header2 = new PowerAuthSignatureHttpHeader(ActivationID ,
//                APP_KEY_LOCAL, signature2 ,
//                "POSSESSION_KNOWLEDGE_BIOMETRY",
//                base64.encode(pa_nonce_2),"2.1");
//
//        String httpAuhtorizationHeader2 = header2.buildHttpHeader();
//
//        Map<String, String> headers2 = new HashMap();
//        headers2.put("Accept", "application/json");
//        headers2.put("Content-Type", "application/json");
//        headers2.put("X-PowerAuth-Authorization", httpAuhtorizationHeader2);
//
//        HttpResponse httpResponse2 = Unirest.
//                get("http://localhost:8080/powerauth-restful-server-spring-0.18.0/pa/signature/validate").
//                headers(headers2).
//                asString();
//
//        System.out.println(httpResponse2.getStatusText());
//        System.out.println(httpResponse2.getHeaders());
//        System.out.println(httpResponse2.getBody());
        String sigData = PowerAuthHttpBody.getSignatureBaseString("POST","/pa/signature/validate", pa_nonce, data);



        return null;
    }

    public  static String commitActivation(String activationId) {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        CommitActivationResponse response = client.commitActivation(request);
        String result = response.getActivationId();


        return result;

    }



    public static KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        return kp;
    }

    public static PushServerClient pushServerClient() {
        PushServerClient client = new PushServerClient();
        client.setServiceBaseUrl("http://localhost:8080/powerauth-push-server");
        return client;
    }






}
