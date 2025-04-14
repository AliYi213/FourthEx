package OrangeHRMTests;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.devtools.DevTools;
import org.openqa.selenium.devtools.v85.network.Network;
import io.github.bonigarcia.wdm.WebDriverManager;
import java.util.Optional;

public class SlowNetworkLoginTest {
    public static void main(String[] args) {
        WebDriverManager.chromedriver().setup();
        ChromeDriver driver = new ChromeDriver();

        try {
            DevTools devTools = driver.getDevTools();
            devTools.createSession();

            devTools.send(Network.enable(Optional.empty(), Optional.empty(), Optional.empty()));
            devTools.send(Network.emulateNetworkConditions(
                    false, 100, 2000, 1000, Optional.empty()
            ));

            driver.get("https://opensource-demo.orangehrmlive.com/web/index.php/auth/login");
            driver.manage().window().maximize();

        } finally {
            driver.quit();
        }
    }
}

