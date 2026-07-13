package hawk.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/api/object")
public class ObjectController {
    
    @PostMapping("/deserialize")
    public String deserializeObject(@RequestBody String base64Data) {
        try {
            // Vulnerable by design - unsafe deserialization
            byte[] serializedData = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
            Object obj = ois.readObject();  // Vulnerable!
            return "Deserialized object: " + obj.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
} 