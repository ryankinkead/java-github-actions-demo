package hawk.controller;

import org.springframework.web.bind.annotation.*;
import javax.naming.directory.*;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import java.util.Hashtable;

@RestController
@RequestMapping("/api/ldap")
public class LdapController {
    
    @GetMapping("/search")
    public String searchUser(@RequestParam("username") String username) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389/dc=example,dc=com");
            
            DirContext ctx = new InitialDirContext(env);
            
            // Vulnerable by design - LDAP injection
            String searchFilter = "(uid=" + username + ")";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<?> results = ctx.search("", searchFilter, constraints);
            return "Search completed for: " + searchFilter;
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
} 