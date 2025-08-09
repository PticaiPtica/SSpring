package ru.academy.homework.sspring.Repository;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.academy.homework.sspring.Entity.Role;

import java.util.Objects;

@Component
public class RoleInitializer implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(RoleInitializer.class);

    private final RoleRepository roleRepository;

    public RoleInitializer(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }


    @Override
    @Transactional
    public void run(String... args) throws Exception {

        logger.info("Initializing Roles ...");

        createRoleIfNotFound("ADMIN");
        createRoleIfNotFound("USER");

        logger.info("Roles initialization complete");
    }

    private void createRoleIfNotFound(String roleName) {
        Objects.requireNonNull(roleName, "Role name cannot be null");

        if (roleName.isBlank()) {
            throw new IllegalArgumentException("Role name cannot be blank");
        }

        try {
            boolean roleExists = roleRepository.existsByName(roleName);

            if (roleExists) {
                logger.debug("Role '{}' already exists - skipping creation", roleName);
                return;
            }

            Role newRole = new Role();
            newRole.setName(roleName.trim());
            Role savedRole = roleRepository.save(newRole);

            logger.info("Successfully created new role: {} (ID: {})",
                    savedRole.getName(), savedRole.getId());
        } catch (Exception ex) {
            logger.error("Failed to create role '{}': {}", roleName, ex.getMessage());
            throw new DataAccessException("Failed to create role: " + roleName, ex) {};
        }
    }
}
