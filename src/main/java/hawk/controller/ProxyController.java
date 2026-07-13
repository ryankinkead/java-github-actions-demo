package hawk.controller;

import org.springframework.web.bind.annotation.*;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;

@RestController
@RequestMapping("/api/proxy")
public class ProxyController {
    
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam("url") String urlString) {
        try {
            // Vulnerable by design - SSRF
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
            return response.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
} 