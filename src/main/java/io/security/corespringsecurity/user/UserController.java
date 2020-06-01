package io.security.corespringsecurity.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

    @GetMapping("/mypage")
    public String myPage() {
        return "user/mypage";
    }
}