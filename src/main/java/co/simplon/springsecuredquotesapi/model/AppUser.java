package co.simplon.springsecuredquotesapi.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "app_user_generator")
    @SequenceGenerator(name = "app_user_generator")
    private Long id;

    @Column(length = 50)
    private String username;

    @JsonIgnore
    @Column(length = 64)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private List<Role> roleList;

    @JsonIgnore
    @OneToMany(mappedBy = "author")
    private List<Quote> personalQuotes = new ArrayList<>();

    public AppUser() {
    }

    public AppUser(String username, String password, List<Role> roleList) {
        this.username = username;
        this.password = password;
        this.roleList = roleList;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public List<Role> getRoleList() {
        return roleList;
    }

    public List<Quote> getPersonalQuotes() {
        return personalQuotes;
    }
}
