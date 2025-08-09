package ru.academy.homework.sspring.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

// AdminController.java
@Controller
@RequestMapping("/admin")
public class AdminController {
    @GetMapping("/dashboard")
    public String adminDashboard() {
        return "admin/dashboard";
    }
}
