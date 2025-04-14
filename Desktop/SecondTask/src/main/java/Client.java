import java.io.*;
import java.net.Socket;

public class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            String xmlFile = "xml.xml";
            String xsltFile = "catalog_transform.xsl";
            dos.writeUTF(xmlFile);
            dos.writeUTF(xsltFile);

            String response = dis.readUTF();
            System.out.println(response);

            int length = dis.readInt();
            byte[] pdfData = new byte[length];
            dis.readFully(pdfData);

            try (FileOutputStream fos = new FileOutputStream("received_output.pdf")) {
                fos.write(pdfData);
            }

            System.out.println("Received PDF file from server.");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
