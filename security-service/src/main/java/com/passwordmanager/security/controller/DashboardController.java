package com.passwordmanager.security.controller;

import com.passwordmanager.security.dto.DashboardResponse;
import com.passwordmanager.security.service.DashboardService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/dashboard")
@CrossOrigin(origins = "*")
public class DashboardController {

    private final DashboardService service;

    public DashboardController(DashboardService service) {
        this.service = service;
    }

    @GetMapping
    public DashboardResponse dashboard(
            @RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId) {
        return service.getDashboard(userId);
    }
}
