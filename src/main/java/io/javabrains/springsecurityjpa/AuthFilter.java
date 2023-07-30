package io.javabrains.springsecurityjpa;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Slf4j
public class AuthFilter extends AbstractAuthenticationProcessingFilter {

    private final JwtService jwtService;


    public AuthFilter(String defaultFilterProcessesUrl, JwtService jwtService) {
        super(defaultFilterProcessesUrl);
        this.jwtService = jwtService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        return null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            var partnerId = ((HttpServletRequest) request).getHeader("partnerId");
            var phone = ((HttpServletRequest) request).getHeader("telephone");
            var authorizationHeader = ((HttpServletRequest) request).getHeader("token");
            var smsCode = ((HttpServletRequest) request).getHeader("smsCode");
             var ip = "192.168.1.1";

            UsernamePasswordAuthenticationToken authToken = null;

            if (StringUtils.hasLength(partnerId)) {
                if (!jwtService.validateToken(authorizationHeader, partnerId, ip)) {
                    ((HttpServletResponse) response).sendError(HttpStatus.UNAUTHORIZED.value(), "Access denied");
                    return;
                }
                var principal = new User(partnerId, "", List.of(SecurityRoles.PARTNER));
                authToken = new UsernamePasswordAuthenticationToken(principal, "", List.of(SecurityRoles.PARTNER));
            }
            else {
                var principal = new User("anonymous", "", List.of(SecurityRoles.SUB_USER));
                authToken = new UsernamePasswordAuthenticationToken(principal, "", List.of(SecurityRoles.SUB_USER));
            }

            var authUser = this.getAuthenticationManager().authenticate(authToken);
            SecurityContextHolder.getContext().setAuthentication(authUser);

        } catch (InvalidRefreshTokenException | InvalidAccessTokenException |
                ExpiredJwtException ex) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
            log.error("Error while generating token", ex);
            throw ex;
        } catch (Exception ex) {
            throw ex;
        }

        chain.doFilter(request, response);
    }
}
