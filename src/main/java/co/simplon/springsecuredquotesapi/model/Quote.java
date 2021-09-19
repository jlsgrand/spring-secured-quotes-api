package co.simplon.springsecuredquotesapi.model;

import javax.persistence.*;

@Entity
public class Quote {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "quote_generator")
    @SequenceGenerator(name = "quote_generator")
    private Long id;

    @Column(length = 100)
    private String movie;

    @Column(length = 1000)
    private String content;

    @ManyToOne
    private AppUser author;

    public Quote() {
    }

    public Quote(String movie, String content, AppUser author) {
        this.movie = movie;
        this.content = content;
        this.author = author;
    }

    public Long getId() {
        return id;
    }

    public String getMovie() {
        return movie;
    }

    public String getContent() {
        return content;
    }

    public AppUser getAuthor() {
        return author;
    }

    public void setAuthor(AppUser author) {
        this.author = author;
    }
}
