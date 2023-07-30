package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.AuthRequest;
import io.javabrains.springsecurityjpa.models.AuthResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@Slf4j
@RequiredArgsConstructor
public class HomeResource {
    private final UserDetailsService UserDetailsService;
    private final JwtService jwtService;

    @GetMapping("/")
    public String home() {
        return ("<h1>Welcome</h1>");
    }

    @GetMapping("/user")
    public String user() {
        return ("<h1>Welcome User</h1>");
    }

    @GetMapping("/admin")
    public String admin() {
        return ("<h1>Welcome Admin</h1>");
    }

    @PostMapping(value = "/api/v1/auth", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getToken(HttpServletRequest request, @RequestBody AuthRequest authRequest) {
        var token = "";
        try {
            token = generateToken(authRequest.getName(), authRequest.getPassword());
        } catch (UsernameNotFoundException usernameNotFoundException) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

//        catch (NotFoundException ex) {
//            log.error(ex.getMessage());
//            return response401();
//        }
//        catch (IncorrectPasswordException ex) {
//            log.error(ex.getMessage());
//            return response404("Logon failed. The logon attempt is unsuccessful, " +
//                    "probably because of a user name or password that is not valid.");
//        }
//        catch (Exception ex) {
//            log.error("Unpredictable error", ex);
//            return response500("Server issue. Error while creating token.");
//        }

        return ResponseEntity.ok(new AuthResponse(token));
    }

    public String generateToken(String userName, String password) {
        log.debug("UserName = {}", userName);

        var user = UserDetailsService.loadUserByUsername(userName);

        if (!user.getPassword().equals(password)) {
            throw new IncorrectPasswordException("Name or password is incorrect");
        }
        String accessToken = jwtService.generateAccessToken(1, userName);

        log.debug("Access token = {}", accessToken);
        return accessToken;
    }
}

