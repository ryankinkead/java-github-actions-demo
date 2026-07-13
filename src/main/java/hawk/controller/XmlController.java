package hawk.controller;

import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

@RestController
@RequestMapping("/api/xml")
public class XmlController {
    
    @PostMapping("/parse")
    public String parseXml(@RequestBody String xmlData) {
        try {
            // Vulnerable by design - XML parsing without disabling XXE
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
            return "XML parsed successfully: " + doc.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "Error parsing XML: " + e.getMessage();
        }
    }
} 