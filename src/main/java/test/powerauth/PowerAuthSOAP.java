package test.powerauth;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.sql.Date;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.google.common.io.BaseEncoding;

import io.getlime.powerauth.soap.ActivationStatus;
import io.getlime.powerauth.soap.CreateActivationRequest;
import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.InitActivationResponse;
import io.getlime.powerauth.soap.PrepareActivationRequest;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilBouncyCastle;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;

@SpringBootApplication
public class PowerAuthSOAP {
	private static BaseEncoding base64 = BaseEncoding.base64();
	private static final String USER_ID = "1234";
	private static final Long APP_ID = 1l;
	private static final String APP_KEY = "Yup56YsItFKBUvD+NaxDkw==";
	private static final String APP_SECRET = "H4zCEKsurTRyuxo3G1nexQ==";

	public static void main(String[] args) {
//		Security.addProvider(new BouncyCastleProvider());
		SpringApplication.run(PowerAuthSOAP.class);
	}

	// https://github.com/lime-company/powerauth-crypto/wiki/Activation 
	@Bean
	public static String start(PowerAuthServiceClient client) throws Exception {
		// 1 - 4
		InitActivationResponse initRes = initiateActivation(client);

		// 5 - 6 optional
		String activationId = initRes.getActivationId();
		String ACTIVATION_ID_SHORT = initRes.getActivationIdShort();
		String ACTIVATION_OTP = initRes.getActivationOTP();
//		String ACTIVATION_SIG = initRes.getActivationSignature();
		System.out.println("Activation ID: " + activationId);
		System.out.println("\"activationIdShort\":\"" + ACTIVATION_ID_SHORT + "\",");
		System.out.printf("\"applicationKey\":\"%s\",%n", APP_KEY);
		//		System.out.println("Activation OTP: " + ACTIVATION_OTP);
		//		System.out.println("Activation sig: " + responseInit.getActivationSignature());

		// 7 - 
		exchangeKey(client, activationId, ACTIVATION_ID_SHORT, ACTIVATION_OTP);

		return null;
	}

	// https://raw.githubusercontent.com/wiki/lime-company/powerauth-crypto/resources/images/sequence_activation_init.png
	public static InitActivationResponse initiateActivation(PowerAuthServiceClient client) {
		// 1 - 4
		InitActivationResponse initRes = client.initActivation(USER_ID, APP_ID, 123l, Date.valueOf("2020-01-01"));
		System.out.print("Status after init: ");
		printStatus(client, initRes.getActivationId());
		return initRes;
	}

	// https://raw.githubusercontent.com/wiki/lime-company/powerauth-crypto/resources/images/sequence_activation_prepare.png
	public static void exchangeKey(PowerAuthServiceClient client, String activationId, String ACTIVATION_ID_SHORT,
			String ACTIVATION_OTP) throws Exception {
		CryptoProviderUtil util = CryptoProviderUtilFactory.getCryptoProviderUtils();
		PowerAuthConfiguration.INSTANCE.setKeyConvertor(util);
		PowerAuthClientActivation activation = new PowerAuthClientActivation();
		KeyGenerator keygen = new KeyGenerator();

		// 7. generate device key pair
		KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
		PrivateKey KEY_DEVICE_PRIVATE = deviceKeyPair.getPrivate();
		PublicKey KEY_DEVICE_PUBLIC = deviceKeyPair.getPublic();

		// 8. client send request: ACTIVATION_ID_SHORT, ACTIVATION_NONCE, C_KEY_DEVICE_PUBLIC, KEY_EPH_PUBLIC
		String masterPublicKey = "BDlM2ynJxocvkt+uUiKWToaPstWr33gm+CZTaqUFLOxOM7SmVdgMuuOluLGhlSjoYm66VVbOW4GRKow6Ins8MQs=";
		PublicKey KEY_SERVER_MASTER_PUBLIC = util.convertBytesToPublicKey(base64.decode(masterPublicKey));

		KeyPair ephKeyPair = activation.generateDeviceKeyPair();
		PrivateKey KEY_EPH_PRIVATE = ephKeyPair.getPrivate();
		PublicKey KEY_EPH_PUBLIC = ephKeyPair.getPublic();
//		SecretKey EPH_KEY = keygen.computeSharedKey(KEY_EPH_PRIVATE, KEY_SERVER_MASTER_PUBLIC);
//		byte[] EPH_KEY = util.convertPublicKeyToBytes(KEY_EPH_PUBLIC);

		byte[] ACTIVATION_NONCE = activation.generateActivationNonce();
		byte[] C_KEY_DEVICE_PUBLIC = activation.encryptDevicePublicKey(KEY_DEVICE_PUBLIC, KEY_EPH_PRIVATE,
				KEY_SERVER_MASTER_PUBLIC, ACTIVATION_OTP, ACTIVATION_ID_SHORT, ACTIVATION_NONCE);
		String ACTIVATION_NONCE_STR = base64.encode(ACTIVATION_NONCE);
		String C_KEY_DEVICE_PUBLIC_STR = base64.encode(C_KEY_DEVICE_PUBLIC);
		String KEY_EPH_PUBLIC_STR = base64.encode(util.convertPublicKeyToBytes(KEY_EPH_PUBLIC));
		System.out.printf("\"activationNonce\":\"%s\",%n", ACTIVATION_NONCE_STR);
		System.out.printf("\"ephemeralPublicKey\":\"%s\",%n", KEY_EPH_PUBLIC_STR);
		System.out.printf("\"encryptedDevicePublicKey\":\"%s\",%n", C_KEY_DEVICE_PUBLIC_STR);

		byte[] APP_SIG = activation.computeApplicationSignature(ACTIVATION_ID_SHORT, ACTIVATION_NONCE,
				C_KEY_DEVICE_PUBLIC, base64.decode(APP_KEY), base64.decode(APP_SECRET));
		String APP_SIG_STR = base64.encode(APP_SIG);
		System.out.printf("\"applicationSignature\":\"%s\",%n", APP_SIG_STR);
		// key exchange
		PrepareActivationRequest prepareReq = new PrepareActivationRequest();
		prepareReq.setActivationName("blah");
		prepareReq.setActivationIdShort(ACTIVATION_ID_SHORT);
		prepareReq.setActivationNonce(ACTIVATION_NONCE_STR);
		prepareReq.setApplicationKey(APP_KEY);
		prepareReq.setApplicationSignature(APP_SIG_STR);
		prepareReq.setEncryptedDevicePublicKey(C_KEY_DEVICE_PUBLIC_STR);
		prepareReq.setEphemeralPublicKey(KEY_EPH_PUBLIC_STR);
		System.out.printf("\"activationName\":\"%s\",%n", prepareReq.getActivationName());

		PrepareActivationResponse activateResponse = client.prepareActivation(prepareReq);
		System.out.print("Status after prepare: ");
		printStatus(client, activationId);

//		SecretKey signingKey = PowerAuthConfiguration.INSTANCE.getKeyConvertor()
//				.convertBytesToSharedSecretKey(base64.decode(APP_SECRET));
//		SecretKey KEY_ENCRYPTION_OTP = keygen.deriveSecretKeyFromPassword(ACTIVATION_OTP,
//				ACTIVATION_ID_SHORT.getBytes("UTF-8"));
//
//		CreateActivationRequest createReq = new CreateActivationRequest();
//		createReq.setUserId(USER_ID);
//		createReq.setActivationName("Activation 1");
//		createReq.setActivationNonce(ACTIVATION_NONCE_STR);
//		createReq.setActivationOtp(ACTIVATION_OTP);
//		createReq.setApplicationId(38l);
//		createReq.setEncryptedDevicePublicKey(C_KEY_DEVICE_PUBLIC_STR);
//		createReq.setEphemeralPublicKey(KEY_EPH_PUBLIC_STR);
//		createReq.setApplicationKey(APP_KEY);
//		createReq.setApplicationSignature(APP_SIG_STR);
//		createReq.setIdentity("createRequest");
//		CreateActivationResponse createRes = client.createActivation(createReq);
	}

	public static void commitActivation() {

	}

	public static void printStatus(PowerAuthServiceClient client, String activationId) {
		GetActivationStatusResponse res = client.getActivationStatus(activationId);
		ActivationStatus status = res.getActivationStatus();
		System.out.println(status.value());
	}
}
