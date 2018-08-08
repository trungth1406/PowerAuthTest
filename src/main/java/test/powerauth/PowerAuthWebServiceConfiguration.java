package test.powerauth;


import com.google.common.io.BaseEncoding;
import io.getlime.powerauth.soap.*;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.bouncycastle.jcajce.provider.digest.SHA1;
import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.bouncycastle.jcajce.provider.util.SecretKeyUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cglib.core.KeyFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import sun.rmi.rmic.Generator;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

@Configuration
@ComponentScan(basePackages = {"io.getlime.security.powerauth"})
public class PowerAuthWebServiceConfiguration {


    @Value("http://localhost:8080/powerauth-java-server/soap/")
    private String powerAuthServiceUrl = "http://localhost:8080/powerauth-java-server/soap/";


    @Bean
    public Jaxb2Marshaller marshaller(){
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("io.getlime.powerauth.soap");
        return marshaller;
    }

    @Bean
    public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
        PowerAuthServiceClient client = new PowerAuthServiceClient();
        client.setDefaultUri(powerAuthServiceUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        return client;
    }




}
