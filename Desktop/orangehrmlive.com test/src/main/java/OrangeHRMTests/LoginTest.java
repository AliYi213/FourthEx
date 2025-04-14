package OrangeHRMTests;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;

public class LoginTest {
        public static void main(String[] args) {
                System.setProperty("webdriver.chrome.driver", "C:\\Users\\Ali\\Desktop\\chromedriver-win64\\chromedriver.exe");

                WebDriver driver = new ChromeDriver();

                try {
                        // Navigate to the login page
                        driver.get("https://opensource-demo.orangehrmlive.com/web/index.php/auth/login");
                        driver.manage().window().maximize();

                        // Add an explicit wait for the username field to be visible and interactable
                        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
                        WebElement usernameField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));

                        // Enter valid credentials (username and password)
                        WebElement passwordField = driver.findElement(By.name("password"));

                        usernameField.sendKeys("Admin");
                        passwordField.sendKeys("admin123");

                        // Click the Login button
                        WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
                        loginButton.click();

                        // Wait for the dashboard to load
                        WebElement dashboardHeader = wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//h6[text()='Dashboard']")));

                        // Verify if the user successfully logs in
                        if (dashboardHeader.isDisplayed()) {
                                System.out.println("Test Passed: User successfully logged in.");
                        } else {
                                System.out.println("Test Failed: Dashboard did not load.");
                        }

                        // Get page source before closing the session, if needed
                        String pageSource = driver.getPageSource();
                        System.out.println("Page source retrieved successfully.");

                } catch (Exception e) {
                        System.out.println("Test Failed due to exception: " + e.getMessage());
                } finally {
                        driver.quit();
                }
        }
}
