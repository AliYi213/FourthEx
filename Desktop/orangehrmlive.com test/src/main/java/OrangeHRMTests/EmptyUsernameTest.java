package OrangeHRMTests;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;

public class EmptyUsernameTest {
    public static void main(String[] args) {
        System.setProperty("webdriver.chrome.driver", "C:\\Users\\Ali\\Desktop\\chromedriver-win64\\chromedriver.exe");
        WebDriver driver = new ChromeDriver();

        try {
            // Navigate to the login page
            driver.get("https://opensource-demo.orangehrmlive.com/web/index.php/auth/login");

            // Maximize the browser window
            driver.manage().window().maximize();

            // Leave username blank, enter valid password
            WebElement passwordField = driver.findElement(By.name("password"));

            passwordField.sendKeys("admin123");

            // Click the Login button
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            loginButton.click();

            // Wait for error message to appear (explicit wait)
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
            WebElement errorMessage = wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//span[contains(text(),'Required')]")));

            // Verify if the error message is displayed
            if (errorMessage.isDisplayed()) {
                System.out.println("Test Passed: Error message displayed for empty username.");
            } else {
                System.out.println("Test Failed: No error message for empty username.");
            }

        } catch (Exception e) {
            System.out.println("Test Failed due to exception: " + e.getMessage());
        } finally {
            driver.quit();
        }
    }
}
