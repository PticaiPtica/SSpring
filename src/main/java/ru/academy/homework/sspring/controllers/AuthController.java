package ru.academy.homework.sspring.controllers;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import ru.academy.homework.sspring.Entity.User;
import ru.academy.homework.sspring.Service.AuthService;
import ru.academy.homework.sspring.Service.UserService;

@Controller
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    // GET /api/auth/login (форма входа)
    @GetMapping("/login")
    public String showLoginForm() {
        return "login"; // имя Thymeleaf-шаблона (login.html)
    }

    // POST /api/auth/login (обработка входа)
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletResponse response
    ) {
        String token = authService.authenticate(username, password);

        // Устанавливаем токен в cookie
        Cookie cookie = new Cookie("token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        return ResponseEntity.ok().build();
    }

    // GET /api/auth/register (форма регистрации)
    @GetMapping("/register")
    public String showRegisterForm() {
        return "register"; // имя Thymeleaf-шаблона (register.html)
    }

    // POST /api/auth/register (обработка регистрации)
    @PostMapping("/register")
    public String register(
            @RequestParam String username,
            @RequestParam String password
    ) {
        User newUser = new User(username,password);
        userService.registerNewUser(newUser,"USER");
        return "redirect:/api/auth/login"; // перенаправление на страницу входа
    }
}

