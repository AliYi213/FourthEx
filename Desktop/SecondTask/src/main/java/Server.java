import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            System.out.println("Server started, waiting for client");
            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                     DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
                     DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream())) {

                    System.out.println("Client connected");

                    String xmlFile = dis.readUTF();
                    String xsltFile = dis.readUTF();
                    String foFile = "catalog_transform.fo";
                    String htmlOutputFile = "output.html";
                    String pdfOutputFile = "output.pdf";
                    Xml.transformXMLToHTML(xmlFile, xsltFile, htmlOutputFile);
                    Xml.transformXMLToFO(xmlFile, xsltFile, foFile);
                    Xml.transformFOToPDF();

                    dos.writeUTF("Transformation complete");

                    File pdfFile = new File(pdfOutputFile);
                    byte[] pdfData = new byte[(int) pdfFile.length()];
                    try (FileInputStream fis = new FileInputStream(pdfFile)) {
                        fis.read(pdfData);
                        dos.writeInt(pdfData.length);
                        dos.write(pdfData);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
