package test.powerauth;



import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = {"ib/settings"})
public class AuthenticationController {

    @Autowired
    private static PowerAuthServiceClient powerAuthServiceClient;

    public static void main(String[] args) {
        powerAuthServiceClient.getSystemStatus();
    }
}
