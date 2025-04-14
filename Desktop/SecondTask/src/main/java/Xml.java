import java.io.File;
import java.io.OutputStream;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.MimeConstants;

public class Xml {

    public static void transformXMLToHTML(String xmlFile, String xsltFile, String outputFile) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        StreamSource xslStream = new StreamSource(new File(xsltFile));
        Transformer transformer = factory.newTransformer(xslStream);
        StreamSource in = new StreamSource(new File(xmlFile));
        StreamResult out = new StreamResult(new File(outputFile));
        transformer.transform(in, out);
    }

    public static void transformXMLToFO(String xmlFile, String xsltFile, String outputFile) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        StreamSource xslStream = new StreamSource(new File(xsltFile));
        Transformer transformer = factory.newTransformer(xslStream);
        StreamSource in = new StreamSource(new File(xmlFile));
        StreamResult out = new StreamResult(new File(outputFile));
        transformer.transform(in, out);
    }

    public static void transformFOToPDF() {
        try {
            FopFactory fopFactory = FopFactory.newInstance(new File(".").toURI());
            TransformerFactory factory = TransformerFactory.newInstance();

            File foFile = new File("C:/Users/Ali/Desktop/SecondTask/catalog_transform.fo");
            StreamSource foSource = new StreamSource(foFile);

            File pdfFile = new File("C:/Users/Ali/Desktop/SecondTask/output.pdf");
            OutputStream out = new java.io.FileOutputStream(pdfFile);

            try {
                Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, out);
                Transformer transformer = factory.newTransformer();

                transformer.transform(foSource, new SAXResult(fop.getDefaultHandler()));
            } finally {
                out.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
