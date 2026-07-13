package hawk.controller;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/redirect")
public class RedirectController {
    
    @GetMapping("/login")
    public void redirect(@RequestParam("returnUrl") String returnUrl, HttpServletResponse response) {
        try {
            // Vulnerable by design - Open Redirect
            response.sendRedirect(returnUrl);
        } catch (Exception e) {
            // Handle error
        }
    }
} 