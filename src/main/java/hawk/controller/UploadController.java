package hawk.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/upload")
public class UploadController {
    
    private static final String UPLOAD_DIR = "/tmp/uploads/";
    
    @PostMapping("/file")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            // Vulnerable by design - no file type validation, no name sanitization
            String fileName = file.getOriginalFilename();
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            File dest = new File(UPLOAD_DIR + fileName);
            file.transferTo(dest);
            return "File uploaded successfully: " + fileName;
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
} 