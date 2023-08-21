package com.Jwtalibou.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
//build my project in an easy way using the design pattern Builder
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user")
//implement karanawa user details wa framework security core eken
//etapsse userdetails ge methood api override karanawa
public class User  implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

//    api methona enum ekak hadanawa role kiyala
//    type eka original hari string use karanna puluwan
//    string nm name (admin ,user)
//    original (1 ,0 )
    @Enumerated(EnumType.STRING)
    private Role role;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    //methana pass word kiyana eka getpassword kiyala enne na mkd api lombok use
// karapu nisa api ekanisa password kiyana eke nama venas karala
// implemt karala ai nama thiuna vidiyata hadanawa
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
