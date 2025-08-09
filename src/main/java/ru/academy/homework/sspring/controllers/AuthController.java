package ru.academy.homework.sspring.controllers;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import ru.academy.homework.sspring.Entity.User;
import ru.academy.homework.sspring.Service.AuthService;
import ru.academy.homework.sspring.Service.UserService;

@Controller
public class AuthController {
    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    @GetMapping("/login")
    public String showLoginForm() {
        return "login";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username,
                                   @RequestParam String password,
                                   HttpServletResponse response) {
        String token = authService.authenticate(username, password);

        // Добавляем токен в cookie для фронта
        Cookie cookie = new Cookie("token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/register")
    public String showRegisterForm() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        userService.registerNewUser(user, "USER");

        return "redirect:/login";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }
}

