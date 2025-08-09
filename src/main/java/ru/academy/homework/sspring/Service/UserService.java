package ru.academy.homework.sspring.Service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.academy.homework.sspring.Entity.Role;
import ru.academy.homework.sspring.Entity.User;

import ru.academy.homework.sspring.JWT.JwtUtil;
import ru.academy.homework.sspring.Repository.RoleRepository;
import ru.academy.homework.sspring.Repository.UserRepository;

import java.util.HashSet;

@Service

public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User registerNewUser(User user, String roleName) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // Получаем роль из базы
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));

        // Инициализируем roles, если еще не инициализирована
        if (user.getRoles() == null) {
            user.setRoles(new HashSet<>());
        }

        // Добавляем роль пользователю
        user.getRoles().add(role);

        return userRepository.save(user);
    }
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }


}


