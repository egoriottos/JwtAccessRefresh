package com.example.jwtaccessrefresh.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v2/project")
public class Controller {
    @GetMapping("/demo")
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("Hello World");
    }
}
