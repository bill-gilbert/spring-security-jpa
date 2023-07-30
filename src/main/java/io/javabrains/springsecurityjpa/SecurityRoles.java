package io.javabrains.springsecurityjpa;

import org.springframework.security.core.GrantedAuthority;

public enum SecurityRoles implements GrantedAuthority {
    ANONYMOUS("ANONYMOUS"), ADMIN("ADMIN"), USER("USER"), SUB_USER("SUB_USER"), PARTNER("PARTNER");

    private final String authority;

    SecurityRoles(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}
