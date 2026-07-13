package hawk.controller;

import hawk.entity.Item;
import hawk.service.SearchService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/items")
public class ItemController {
    
    private final SearchService searchService;
    
    @Autowired
    public ItemController(SearchService searchService) {
        this.searchService = searchService;
    }
    
    @GetMapping("/search/price")
    public List<Item> searchByPrice(@RequestParam("min") String minPrice) {
        // Vulnerable by design - SQL Injection
        return searchService.searchByPrice(minPrice);
    }
} 