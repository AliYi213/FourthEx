package OrangeHRMTests;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;

public class InvalidUsernametest {
    public static void main(String[] args) {
        System.setProperty("webdriver.chrome.driver", "C:\\Users\\Ali\\Desktop\\chromedriver-win64\\chromedriver.exe");

        WebDriver driver = new ChromeDriver();

        try {
            driver.get("https://opensource-demo.orangehrmlive.com/web/index.php/auth/login");
            driver.manage().window().maximize();

            // Enter invalid username and valid password
            WebElement usernameField = driver.findElement(By.name("username"));
            WebElement passwordField = driver.findElement(By.name("password"));

            usernameField.sendKeys("InvalidUser");
            passwordField.sendKeys("admin123");

            // Click the Login button
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            loginButton.click();

            // Wait for error message to appear (explicit wait)
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
            WebElement errorMessage = wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//p[contains(text(),'Invalid credentials')]")));

            // Verify if the error message is displayed
            if (errorMessage.isDisplayed()) {
                System.out.println("Test Passed: Error message displayed for invalid username.");
            } else {
                System.out.println("Test Failed: No error message for invalid username.");
            }

        } catch (Exception e) {
            System.out.println("Test Failed due to exception: " + e.getMessage());
        } finally {
            driver.quit();
        }
    }
}
