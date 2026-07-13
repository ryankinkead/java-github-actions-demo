package hawk.controller;

import org.springframework.web.bind.annotation.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

@RestController
@RequestMapping("/api/template")
public class TemplateController {
    
    @GetMapping("/render")
    public String renderTemplate(@RequestParam("template") String templateUrl) {
        try {
            // Vulnerable by design - Remote File Inclusion
            URL url = new URL(templateUrl);
            Path tempFile = Files.createTempFile("template", ".html");
            Files.copy(url.openStream(), tempFile, StandardCopyOption.REPLACE_EXISTING);
            
            String content = new String(Files.readAllBytes(tempFile));
            Files.delete(tempFile);
            
            return content;  // In a real app, this would be processed as a template
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
} 