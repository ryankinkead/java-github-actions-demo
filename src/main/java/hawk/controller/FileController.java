package hawk.controller;

import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.File;

@RestController
@RequestMapping("/api/files")
public class FileController {
    
    private static final String BASE_PATH = "/tmp/";  // Vulnerable by design
    
    @GetMapping("/download")
    public ResponseEntity<FileSystemResource> downloadFile(@RequestParam("filename") String filename) {
        // Vulnerable by design - no path validation
        File file = new File(BASE_PATH + filename);
        
        return ResponseEntity
                .ok()
                .body(new FileSystemResource(file));
    }
} 