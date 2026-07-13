package hawk.controller;

import hawk.entity.User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @PostMapping("/create")
    public User createUser(@RequestBody User user) {
        // Vulnerable by design - mass assignment
        // Allows setting any field including isAdmin and role
        return user;  // In real app, this would save to database
    }
} 