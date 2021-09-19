package co.simplon.springsecuredquotesapi.repository;

import co.simplon.springsecuredquotesapi.model.Quote;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface QuoteRepository extends JpaRepository<Quote, Long> {

}
